/*
Copyright 2025-2026 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Package ibmcsidriver ...
package ibmcsidriver

// node_bms.go contains all Bare Metal Server (BMS) specific logic for the CSI
// node server.  BMS volumes attach via NVMe-oF over TCP with TLS 1.3 (SDP
// protocol) rather than virtio/xvd used by VSI nodes.
//
// Key design decisions:
//   - Detection:   presence of publishContext["bms-subsystem-nqn"] → BMS path.
//   - PSK security: publishContext carries RSA ciphertext ("bms-encrypted-secret");
//     the node decrypts it locally using BMSPrivKey loaded at startup.
//   - Shared subsystem: multiple volumes may share a single NVMe subsystem NQN.
//     subsysRefCount prevents premature disconnect (OPT 3 / OPT 4).
//   - State file:  written at NodeStageVolume, read at NodeUnstageVolume because
//     NodeUnstageVolumeRequest carries no publishContext (CSI spec §3.4.2).
//   - Device path: /dev/disk/by-id/nvme-uuid.<namespace-uuid>, where the UUID is
//     the volume ID without its "r134-" style prefix (full ID kept as fallback).

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	csi "github.com/container-storage-interface/spec/lib/go/csi"
	"go.uber.org/zap"
	mount "k8s.io/mount-utils"
)

// bmsDevicePathPrefix is the stable by-id path for NVMe volumes on BMS nodes.
// The link name is built by the kernel from the namespace UUID, which is the
// UUID part of the VPC volume ID (the volume ID without its "r134-" style
// region prefix). The full path is: /dev/disk/by-id/nvme-uuid.<namespace-uuid>
const bmsDevicePathPrefix = "/dev/disk/by-id/nvme-uuid."

// uuidLen is the length of a canonical textual UUID (8-4-4-4-12).
const uuidLen = 36

// bmsDevicePathCandidates returns the by-id paths to look for, most likely first.
//
// The kernel names the link after the namespace UUID, e.g. for volume
// "r134-342f4b28-b6f0-4b23-b9c5-0cdf036f4948" it creates
// "nvme-uuid.342f4b28-b6f0-4b23-b9c5-0cdf036f4948" (no "r134-"). The full
// volume ID is kept as a fallback in case a different image/kernel uses it.
func bmsDevicePathCandidates(volumeID string) []string {
	var paths []string
	// The UUID is always the last 36 chars, preceded by the "-" that separates
	// it from the region prefix. This does not depend on the prefix length.
	if n := len(volumeID); n > uuidLen+1 && volumeID[n-uuidLen-1] == '-' {
		paths = append(paths, bmsDevicePathPrefix+volumeID[n-uuidLen:])
	}
	return append(paths, bmsDevicePathPrefix+volumeID)
}

// isNVMeAlreadyConnected reports whether `nvme connect` failed only because the
// controller for this subsystem/address/host is already connected. That is not
// a failure for staging: the subsystem's namespaces are already present.
func isNVMeAlreadyConnected(output string) bool {
	return strings.Contains(strings.ToLower(output), "already connected")
}

// bmsDeviceWaitTimeout is the maximum time to wait for the NVMe device path to
// appear after a successful nvme connect.
const bmsDeviceWaitTimeout = 60 * time.Second

// bmsDeviceWaitInterval is the polling interval while waiting for the device.
const bmsDeviceWaitInterval = 2 * time.Second

// ─── State file helpers ───────────────────────────────────────────────────────

// writeBMSStateFile writes subsysNQN to the per-volume state file.
// The file is used by NodeUnstageVolume to recover the NQN because
// NodeUnstageVolumeRequest carries no publishContext (CSI spec §3.4.2).
func writeBMSStateFile(volumeID, subsysNQN string) error {
	if err := os.MkdirAll(bmsStateDir, 0o750); err != nil {
		return fmt.Errorf("writeBMSStateFile: failed to create state dir %s: %w", bmsStateDir, err)
	}
	path := filepath.Join(bmsStateDir, volumeID)
	if err := os.WriteFile(path, []byte(subsysNQN), 0o640); err != nil {
		return fmt.Errorf("writeBMSStateFile: failed to write %s: %w", path, err)
	}
	return nil
}

// readBMSStateFile returns the subsysNQN stored for volumeID.
// Returns ("", err) if the file does not exist (non-BMS volume).
func readBMSStateFile(volumeID string) (string, error) {
	path := filepath.Join(bmsStateDir, volumeID)
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

// removeBMSStateFile removes the per-volume state file after a successful
// NodeUnstageVolume.  A missing file is silently ignored (idempotent).
func removeBMSStateFile(volumeID string) {
	_ = os.Remove(filepath.Join(bmsStateDir, volumeID))
}

// ─── RSA decryption ───────────────────────────────────────────────────────────

// decryptBMSSecret decrypts the base64-encoded RSA ciphertext produced by the
// controller (using the cluster admin's public key) and returns the plaintext
// PSK string.
func decryptBMSSecret(privKeyPEM []byte, cipherB64 string) (string, error) {
	// Decode PEM block
	block, _ := pem.Decode(privKeyPEM)
	if block == nil {
		return "", fmt.Errorf("decryptBMSSecret: failed to decode PEM block from private key")
	}

	// Parse PKCS#1 or PKCS#8 private key
	var privKey *rsa.PrivateKey
	switch block.Type {
	case "RSA PRIVATE KEY":
		key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return "", fmt.Errorf("decryptBMSSecret: failed to parse PKCS1 private key: %w", err) // pragma: allowlist secret
		}
		privKey = key
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return "", fmt.Errorf("decryptBMSSecret: failed to parse PKCS8 private key: %w", err) // pragma: allowlist secret
		}
		rsaKey, ok := key.(*rsa.PrivateKey)
		if !ok {
			return "", fmt.Errorf("decryptBMSSecret: PKCS8 key is not RSA") // pragma: allowlist secret
		}
		privKey = rsaKey
	default:
		return "", fmt.Errorf("decryptBMSSecret: unsupported PEM block type: %s", block.Type) // pragma: allowlist secret
	}

	// base64-decode the ciphertext
	cipherBytes, err := base64.StdEncoding.DecodeString(cipherB64)
	if err != nil {
		return "", fmt.Errorf("decryptBMSSecret: failed to base64-decode ciphertext: %w", err) // pragma: allowlist secret
	}

	// Try RSA-OAEP (SHA-256) first. The staging VPC API has been observed to
	// encrypt the PSK with PKCS#1 v1.5 instead, so fall back to that if OAEP fails.
	plaintext, oaepErr := rsa.DecryptOAEP(sha256.New(), rand.Reader, privKey, cipherBytes, nil)
	if oaepErr == nil {
		return string(plaintext), nil
	}
	// we can remove this
	plaintext, pkcsErr := rsa.DecryptPKCS1v15(rand.Reader, privKey, cipherBytes)
	if pkcsErr != nil {
		return "", fmt.Errorf("decryptBMSSecret: RSA decrypt failed (OAEP-SHA256: %v; PKCS1v15: %v)", oaepErr, pkcsErr) // pragma: allowlist secret
	}
	return string(plaintext), nil
}

// ─── NVMe-oF helpers ─────────────────────────────────────────────────────────

// nvmeCheckTLSKey inserts the PSK into the Linux kernel keyring for the given
// host/subsystem NQN pair before calling nvme connect.
//
// Command:
//
//	nvme check-tls-key --hostnqn <hostNQN> --subsysnqn <subsysNQN> \
//	  --identity 0 --keydata <psk> --insert
//
// This must be called once per subsystem before the first nvme connect so the
// kernel NVMe/TCP driver can hand the key to tlshd for TLS 1.3 negotiation.
func nvmeCheckTLSKey(ctxLogger *zap.Logger, hostNQN, subsysNQN, psk string) error {
	args := []string{
		"check-tls-key",
		"--hostnqn", hostNQN,
		"--subsysnqn", subsysNQN,
		"--identity", "0",
		"--keydata", psk,
		"--insert",
	}
	out, err := exec.Command("nvme", args...).CombinedOutput() // #nosec G204
	if err != nil {
		return fmt.Errorf("nvmeCheckTLSKey: failed for subsys %s: %s: %w", subsysNQN, string(out), err)
	}
	ctxLogger.Info("nvmeCheckTLSKey: PSK inserted successfully", zap.String("hostNQN", hostNQN), zap.String("subsysNQN", subsysNQN))
	return nil
}

// nvmeConnect runs `nvme connect` for the given subsystem.
// It is called only when subsysRefCount transitions from 0 → 1 (first volume
// on this subsystem).  Subsequent volumes sharing the same subsystem reuse the
// existing connection (OPT 3).
//
// The diagram specifies:
//
//	nvme connect -t tcp -n <subsysNQN> -a <ip> -s 4420 --hostnqn <hostNQN> --tls
//
// --hostnqn pins the initiator NQN read from /etc/nvme/hostnqn (mounted from host).
// --tls tells the kernel to use TLS 1.3 (via tlshd); the PSK was already
// inserted into the keyring by nvmeCheckTLSKey.
// targetIPs is a comma-separated list; we connect to EVERY IP, not just the
// first that works. The target reports a per-path ANA state, and a volume's
// namespace is accessible through only some of the IPs (the others report
// "inaccessible" and the kernel creates no block device for it). Connecting
// all paths lets any volume of the subsystem find its accessible path.
// An IP that is already connected counts as connected. The call fails only if
// no IP could be connected.
func nvmeConnect(ctxLogger *zap.Logger, hostNQN, subsysNQN, targetIPs string) error {
	ips := strings.Split(targetIPs, ",")
	if len(ips) == 0 || (len(ips) == 1 && ips[0] == "") {
		return fmt.Errorf("nvmeConnect: no target IPs provided for subsystem %s", subsysNQN)
	}

	connected := 0
	for _, ip := range ips {
		ip = strings.TrimSpace(ip)
		if ip == "" {
			//todo: logline
			continue
		}
		if err := nvmeConnectByIP(ctxLogger, hostNQN, subsysNQN, ip); err != nil {
			ctxLogger.Warn("nvmeConnect: nvme connect attempt failed (continuing with other IPs)",
				zap.String("ip", ip), zap.Error(err))
			continue
		}
		connected++
	}
	if connected == 0 {
		return fmt.Errorf("nvmeConnect: all target IPs failed for subsystem %s", subsysNQN)
	}
	return nil
}

// nvmeConnectByIP runs `nvme connect` for a single target IP. It returns nil
// on success, and also when the address is already connected (e.g. retry of a
// previous NodeStageVolume, or a connection that outlived a driver restart) so
// that staging is idempotent. Any other failure is returned with the nvme
// output included.
func nvmeConnectByIP(ctxLogger *zap.Logger, hostNQN, subsysNQN, ip string) error {
	args := []string{
		"connect",
		"--transport", "tcp",
		"--traddr", ip,
		"--trsvcid", "4420",
		"--nqn", subsysNQN,
		"--hostnqn", hostNQN,
		"--tls",
	}
	ctxLogger.Info("nvmeConnectByIP: executing nvme connect",
		zap.String("subsysNQN", subsysNQN),
		zap.String("hostNQN", hostNQN),
		zap.String("targetIP", ip),
		zap.String("command", "nvme "+strings.Join(args, " ")))
	start := time.Now()
	out, err := nvmeRun(args...)
	output := strings.TrimSpace(string(out))
	if err != nil && isNVMeAlreadyConnected(output) {
		ctxLogger.Info("nvmeConnectByIP: address already connected — counting as connected",
			zap.String("ip", ip), zap.String("output", output),
			zap.Duration("elapsed", time.Since(start)))
		return nil
	}
	if err != nil {
		return fmt.Errorf("nvmeConnectByIP: nvme connect to %s failed after %s: %s: %w ", ip, time.Since(start), output, err)
	}
	ctxLogger.Info("nvmeConnectByIP: nvme connect succeeded",
		zap.String("ip", ip), zap.String("output", output),
		zap.Duration("elapsed", time.Since(start)))
	return nil
}

// nvmeRun runs the nvme CLI and returns its combined output. A variable so
// tests can replace it.
var nvmeRun = func(args ...string) ([]byte, error) {
	return exec.Command("nvme", args...).CombinedOutput() // #nosec G204
}

// nvmeDisconnect runs `nvme disconnect` for the given subsystem NQN.
// Called only when subsysRefCount reaches 0 (last volume on subsystem) (OPT 4).
func nvmeDisconnect(ctxLogger *zap.Logger, subsysNQN string) error {
	out, err := exec.Command("nvme", "disconnect", "--nqn", subsysNQN).CombinedOutput() // #nosec G204
	if err != nil {
		return fmt.Errorf("nvmeDisconnect: failed for subsystem %s: %s: %w", subsysNQN, string(out), err)
	}
	ctxLogger.Info("nvmeDisconnect: succeeded", zap.String("subsysNQN", subsysNQN))
	return nil
}

// waitForBMSDevicePath polls until one of the candidate NVMe device paths (see
// bmsDevicePathCandidates) appears under /dev/disk/by-id or the timeout is
// exceeded.
func waitForBMSDevicePath(ctxLogger *zap.Logger, volumeID string) (string, error) {
	candidates := bmsDevicePathCandidates(volumeID)
	deadline := time.Now().Add(bmsDeviceWaitTimeout)
	for time.Now().Before(deadline) {
		for _, devicePath := range candidates {
			if _, err := os.Stat(devicePath); err == nil {
				ctxLogger.Info("waitForBMSDevicePath: device path appeared",
					zap.String("devicePath", devicePath))
				return devicePath, nil
			}
		}
		time.Sleep(bmsDeviceWaitInterval)
	}
	return "", fmt.Errorf("waitForBMSDevicePath: none of %v appeared within %s",
		candidates, bmsDeviceWaitTimeout)
}

// ─── NodeStageVolume BMS branch ───────────────────────────────────────────────

// nodeStageVolumeBMS handles the BMS-specific part of NodeStageVolume:
// PSK decryption, NVMe subsystem connect, device path wait, and state file.
//
// It returns the resolved device path (e.g. /dev/disk/by-id/nvme-uuid.<id>)
// so that NodeStageVolume can run the shared format+mount+resize tail used
// by both BMS and VSI paths — no duplication.
//
// Flow:
//  1. Decrypt PSK from publishContext["bms-encrypted-secret"] using BMSPrivKey.
//  2. subsysRefCount: connect only on first volume on this subsystem.
//  3. Wait for the NVMe device path to appear.
//  4. Write the state file (volumeID → subsysNQN) for NodeUnstageVolume.
//  5. Return devicePath → caller runs findDevicePathSource+FormatAndMount+Resize.
func (csiNS *CSINodeServer) nodeStageVolumeBMS(
	ctx context.Context,
	ctxLogger *zap.Logger,
	requestID string,
	req *csi.NodeStageVolumeRequest,
	volumeID, stagingTargetPath string,
	publishContext map[string]string,
) (string, error) {
	subsysNQN := publishContext[PublishInfoBMSSubsystemNQN]
	targetIPs := publishContext[PublishInfoBMSTargetIPs]
	hostNQN := publishContext[PublishInfoBMSHostNQN]
	encryptedSecret := publishContext[PublishInfoBMSEncryptedSecret]

	ctxLogger.Info("nodeStageVolumeBMS: starting BMS NVMe-oF stage",
		zap.String("volumeID", volumeID),
		zap.String("subsysNQN", subsysNQN),
		zap.String("hostNQN", hostNQN),
		zap.String("targetIPs", targetIPs))

	// Step 1: Decrypt PSK (skip if no private key loaded — non-BMS node guard)
	var psk string
	if len(csiNS.BMSPrivKey) > 0 && encryptedSecret != "" {
		var err error
		psk, err = decryptBMSSecret(csiNS.BMSPrivKey, encryptedSecret)
		if err != nil {
			return "", fmt.Errorf("nodeStageVolumeBMS: failed to decrypt PSK for volume %s: %w", volumeID, err)
		}
		ctxLogger.Info("nodeStageVolumeBMS: PSK decrypted successfully",
			zap.String("volumeID", volumeID),
			zap.Int("pskLen", len(psk)),
			zap.Bool("pskFormatOK", strings.HasPrefix(psk, "NVMeTLSkey-1:")))
	} else {
		ctxLogger.Warn("nodeStageVolumeBMS: no PSK available — connecting without TLS key",
			zap.String("volumeID", volumeID))
	}

	// Step 2: Reference-count the subsystem; connect only on first volume.
	//
	// The lock is held across the entire check-tls-key + nvme connect sequence
	// to prevent a concurrent NodeStageVolume from observing count=1 and
	// skipping connect before the connection is actually established.
	csiNS.subsysMu.Lock()
	count := csiNS.subsysRefCount[subsysNQN]

	if count == 0 {
		if psk != "" {
			if err := nvmeCheckTLSKey(ctxLogger, hostNQN, subsysNQN, psk); err != nil {
				csiNS.subsysMu.Unlock()
				return "", fmt.Errorf("nodeStageVolumeBMS: nvme check-tls-key failed for volume %s: %w", volumeID, err)
			}
		}

		if err := nvmeConnect(ctxLogger, hostNQN, subsysNQN, targetIPs); err != nil {
			csiNS.subsysMu.Unlock()
			return "", fmt.Errorf("nodeStageVolumeBMS: nvme connect failed for volume %s: %w", volumeID, err)
		}
	} else {
		ctxLogger.Info("nodeStageVolumeBMS: subsystem already connected — reusing (OPT 3)",
			zap.String("subsysNQN", subsysNQN), zap.Int("refCount", count+1))
	}

	// Increment only after successful connect (or reuse).
	csiNS.subsysRefCount[subsysNQN] = count + 1
	csiNS.subsysMu.Unlock()

	// Step 3: Wait for device path.
	devicePath, err := waitForBMSDevicePath(ctxLogger, volumeID)
	if err != nil {
		// Roll back ref count; disconnect if we were the first.
		csiNS.subsysMu.Lock()
		csiNS.subsysRefCount[subsysNQN]--
		remaining := csiNS.subsysRefCount[subsysNQN]
		csiNS.subsysMu.Unlock()
		if remaining == 0 && count == 0 {
			_ = nvmeDisconnect(ctxLogger, subsysNQN)
		}
		return "", fmt.Errorf("nodeStageVolumeBMS: device path wait failed for volume %s: %w", volumeID, err)
	}

	// Step 4: Write state file so NodeUnstageVolume can recover subsysNQN.
	// NodeUnstageVolumeRequest carries no publishContext (CSI spec §3.4.2).
	if err := writeBMSStateFile(volumeID, subsysNQN); err != nil {
		ctxLogger.Warn("nodeStageVolumeBMS: failed to write state file (non-fatal)",
			zap.String("volumeID", volumeID), zap.Error(err))
	}

	// Return the device path; NodeStageVolume runs the shared
	// findDevicePathSource + safety-check + FormatAndMount + Resize tail.
	return devicePath, nil
}

// ─── NodeUnstageVolume BMS branch ─────────────────────────────────────────────

// nodeUnstageVolumeBMS handles NodeUnstageVolume for BMS NVMe-oF/TCP volumes.
//
// Flow:
//  1. Unmount the staging target path.
//  2. Decrement subsysRefCount; if count reaches 0 call nvme disconnect.
//  3. Remove the per-volume state file.
func (csiNS *CSINodeServer) nodeUnstageVolumeBMS(
	ctx context.Context,
	ctxLogger *zap.Logger,
	requestID string,
	volumeID, stagingTargetPath, subsysNQN string,
) (*csi.NodeUnstageVolumeResponse, error) {
	ctxLogger.Info("nodeUnstageVolumeBMS: starting BMS NVMe-oF unstage",
		zap.String("volumeID", volumeID),
		zap.String("subsysNQN", subsysNQN),
		zap.String("stagingTargetPath", stagingTargetPath))

	// Step 1: Unmount staging target path.
	if err := mount.CleanupMountPoint(stagingTargetPath, csiNS.Mounter, false); err != nil {
		return nil, fmt.Errorf("nodeUnstageVolumeBMS: unmount failed for volume %s at %s: %w",
			volumeID, stagingTargetPath, err)
	}

	// Step 2: Decrement subsystem ref count; disconnect when last volume leaves.
	csiNS.subsysMu.Lock()
	count := csiNS.subsysRefCount[subsysNQN]
	if count > 0 {
		count--
		csiNS.subsysRefCount[subsysNQN] = count
	}
	csiNS.subsysMu.Unlock()

	if count == 0 {
		ctxLogger.Info("nodeUnstageVolumeBMS: last volume on subsystem — calling nvme disconnect (OPT 4)",
			zap.String("subsysNQN", subsysNQN))
		if err := nvmeDisconnect(ctxLogger, subsysNQN); err != nil {
			// Log and continue — volume is already unmounted; a stale NVMe
			// connection is recoverable on the next attach cycle.
			ctxLogger.Warn("nodeUnstageVolumeBMS: nvme disconnect failed (non-fatal, stale connection may remain)",
				zap.String("subsysNQN", subsysNQN), zap.Error(err))
		}
		// Clean up the map entry to avoid unbounded growth.
		csiNS.subsysMu.Lock()
		delete(csiNS.subsysRefCount, subsysNQN)
		csiNS.subsysMu.Unlock()
	} else {
		ctxLogger.Info("nodeUnstageVolumeBMS: other volumes still using subsystem — skipping disconnect (OPT 4)",
			zap.String("subsysNQN", subsysNQN), zap.Int("remainingRefCount", count))
	}

	// Step 3: Remove state file.
	removeBMSStateFile(volumeID)

	ctxLogger.Info("nodeUnstageVolumeBMS: successfully unstaged BMS volume",
		zap.String("volumeID", volumeID))
	return &csi.NodeUnstageVolumeResponse{}, nil
}
