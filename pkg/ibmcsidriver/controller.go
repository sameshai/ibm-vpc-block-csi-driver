/*
Copyright 2025 The Kubernetes Authors.

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

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	commonError "github.com/IBM/ibm-csi-common/pkg/messages"
	"github.com/IBM/ibm-csi-common/pkg/metrics"
	"github.com/IBM/ibm-csi-common/pkg/utils"
	"github.com/IBM/ibmcloud-volume-interface/lib/provider"
	providerError "github.com/IBM/ibmcloud-volume-interface/lib/utils"
	utilReasonCode "github.com/IBM/ibmcloud-volume-interface/lib/utils/reasoncode"
	userError "github.com/IBM/ibmcloud-volume-vpc/common/messages"
	cloudProvider "github.com/IBM/ibmcloud-volume-vpc/pkg/ibmcloudprovider"
	csi "github.com/container-storage-interface/spec/lib/go/csi"
	"go.uber.org/zap"
)

// CSIControllerServer ...
type CSIControllerServer struct {
	Driver      *IBMCSIDriver
	CSIProvider cloudProvider.CloudProviderInterface
	mutex       utils.LockStore
	csi.UnimplementedControllerServer

	// bmsCacheMu guards bmsCacheHostNQN and bmsCacheSecret.
	bmsCacheMu sync.RWMutex
	// bmsCacheHostNQN maps BMS instance ID → host NQN (nvme_qualified_name).
	// bmsCacheSecret maps BMS instance ID → RSA-encrypted PSK ciphertext.
	// Both are ephemeral in-memory caches: populated on first attach per server,
	// cleared on controller restart → triggers a fresh rotate+GetBMSServer on
	// the next attach, which is the correct security behavior.
	bmsCacheHostNQN map[string]string
	bmsCacheSecret  map[string]string
}

const (
	// PublishInfoVolumeID ...
	PublishInfoVolumeID = "volume-id"

	// PublishInfoNodeID ...
	PublishInfoNodeID = "node-id"

	// PublishInfoStatus ...
	PublishInfoStatus = "attach-status"

	// PublishInfoDevicePath ...
	PublishInfoDevicePath = "device-path"

	// PublishInfoRequestID ...
	PublishInfoRequestID = "request-id"

	// PublishInfoBMSHostNQN is the BMS node host NQN — passed to NodeStageVolume via publishContext
	PublishInfoBMSHostNQN = "bms-host-nqn"

	// PublishInfoBMSSubsystemNQN is the BMS volume subsystem NQN — passed to NodeStageVolume via publishContext
	PublishInfoBMSSubsystemNQN = "bms-subsystem-nqn"

	// PublishInfoBMSTargetIPs is the comma-separated list of NVMe-oF target IPs — passed to NodeStageVolume via publishContext
	PublishInfoBMSTargetIPs = "bms-target-ips"

	// PublishInfoBMSEncryptedSecret is the RSA-encrypted PSK (ciphertext only, never plaintext)
	// passed to NodeStageVolume via publishContext. The node decrypts locally with rsa_private_key.
	PublishInfoBMSEncryptedSecret = "bms-encrypted-secret" // pragma: allowlist secret

)

var _ csi.ControllerServer = &CSIControllerServer{}

// CreateVolume ...
func (csiCS *CSIControllerServer) CreateVolume(ctx context.Context, req *csi.CreateVolumeRequest) (*csi.CreateVolumeResponse, error) {
	ctxLogger, requestID := utils.GetContextLogger(ctx, false)
	// populate requestID in the context
	ctx = context.WithValue(ctx, provider.RequestID, requestID)
	ctxLogger.Info("CSIControllerServer-CreateVolume... ", zap.Reflect("Request", req))
	defer metrics.UpdateDurationFromStart(ctxLogger, "CreateVolume", time.Now())

	// Check basic parameters validations i.e PVC name given
	name := req.GetName()
	if len(name) == 0 {
		return nil, commonError.GetCSIError(ctxLogger, commonError.MissingVolumeName, requestID, nil)
	}

	// check volume capabilities
	volumeCapabilities := req.GetVolumeCapabilities()
	if len(volumeCapabilities) == 0 {
		return nil, commonError.GetCSIError(ctxLogger, commonError.NoVolumeCapabilities, requestID, nil)
	}

	// Validate volume capabilities, are all capabilities supported by driver or not
	if !areVolumeCapabilitiesSupported(req.GetVolumeCapabilities(), csiCS.Driver.vcap) {
		return nil, commonError.GetCSIError(ctxLogger, commonError.VolumeCapabilitiesNotSupported, requestID, nil)
	}

	// Get volume input Parameters
	requestedVolume, err := getVolumeParameters(ctxLogger, req, csiCS.CSIProvider.GetConfig())
	if requestedVolume != nil {
		// For logging mask VolumeEncryptionKey
		// Create copy of the requestedVolume
		tempReqVol := (*requestedVolume)
		// Mask VolumeEncryptionKey
		if requestedVolume.VolumeEncryptionKey != nil {
			tempReqVol.VolumeEncryptionKey = &provider.VolumeEncryptionKey{CRN: "********"}
		}
		ctxLogger.Info("Volume request", zap.Reflect("Volume", tempReqVol))
	}

	if err != nil {
		ctxLogger.Error("Unable to extract parameters", zap.Error(err))
		return nil, commonError.GetCSIError(ctxLogger, commonError.InvalidParameters, requestID, err)
	}

	// TODO: Determine Zones and Region for the disk

	// Validate if volume Already Exists
	session, err := csiCS.CSIProvider.GetProviderSession(ctx, ctxLogger)
	if err != nil {
		if userError.GetUserErrorCode(err) == string(utilReasonCode.EndpointNotReachable) {
			return nil, commonError.GetCSIError(ctxLogger, commonError.EndpointNotReachable, requestID, err)
		}
		if userError.GetUserErrorCode(err) == string(utilReasonCode.Timeout) {
			return nil, commonError.GetCSIError(ctxLogger, commonError.Timeout, requestID, err)
		}
		return nil, commonError.GetCSIError(ctxLogger, commonError.InternalError, requestID, err)
	}

	volumeSource := req.GetVolumeContentSource()
	if volumeSource != nil {
		if _, ok := volumeSource.GetType().(*csi.VolumeContentSource_Snapshot); !ok {
			return nil, commonError.GetCSIError(ctxLogger, commonError.UnsupportedVolumeContentSource, requestID, nil)
		}
		sourceSnapshot := volumeSource.GetSnapshot()
		if sourceSnapshot == nil {
			return nil, commonError.GetCSIError(ctxLogger, commonError.VolumeInvalidArguments, requestID, nil)
		}
		snapshotIdentifier := sourceSnapshot.GetSnapshotId()
		// Remove all whitespaces and search crn: string at 0th position
		// to finalise that user provided crn or not
		if strings.Index(strings.ReplaceAll(snapshotIdentifier, " ", ""), "crn:") == 0 {
			requestedVolume.SnapshotCRN = snapshotIdentifier
		} else {
			requestedVolume.SnapshotID = snapshotIdentifier
		}
	}

	existingVol, err := checkIfVolumeExists(session, *requestedVolume, ctxLogger)
	if existingVol != nil && err == nil {
		ctxLogger.Info("Volume already exists", zap.Reflect("ExistingVolume", existingVol))
		if existingVol.Capacity != nil && requestedVolume.Capacity != nil && *existingVol.Capacity == *requestedVolume.Capacity {
			return createCSIVolumeResponse(*existingVol, int64(*(existingVol.Capacity)*utils.GB), nil, csiCS.CSIProvider.GetClusterID(), csiCS.Driver.region), nil
		}
		return nil, commonError.GetCSIError(ctxLogger, commonError.VolumeAlreadyExists, requestID, err, name, *requestedVolume.Capacity)
	}

	// Create volume
	volumeObj, err := session.CreateVolume(*requestedVolume)
	if err != nil {
		if providerError.RetrivalFailed == providerError.GetErrorType(err) {
			return nil, commonError.GetCSIError(ctxLogger, commonError.ObjectNotFound, requestID, err, "creation")
		}
		return nil, commonError.GetCSIBackendError(ctxLogger, requestID, err)
	}

	// return csi volume object
	return createCSIVolumeResponse(*volumeObj, int64(*(requestedVolume.Capacity)*utils.GB), nil, csiCS.CSIProvider.GetClusterID(), csiCS.Driver.region), nil
}

// DeleteVolume ...
func (csiCS *CSIControllerServer) DeleteVolume(ctx context.Context, req *csi.DeleteVolumeRequest) (*csi.DeleteVolumeResponse, error) {
	ctxLogger, requestID := utils.GetContextLogger(ctx, false)
	// populate requestID in the context
	ctx = context.WithValue(ctx, provider.RequestID, requestID)
	defer metrics.UpdateDurationFromStart(ctxLogger, "DeleteVolume", time.Now())
	ctxLogger.Info("CSIControllerServer-DeleteVolume... ", zap.Reflect("Request", req))

	// Validate arguments
	volumeID := req.GetVolumeId()
	if len(volumeID) == 0 {
		return nil, commonError.GetCSIError(ctxLogger, commonError.EmptyVolumeID, requestID, nil)
	}

	// TODO:~ Following could be enhancement although currect way is working fine
	// Get the volume name by using volume ID
	// and delete volume by name

	// get the session
	session, err := csiCS.CSIProvider.GetProviderSession(ctx, ctxLogger)
	if err != nil {
		return nil, commonError.GetCSIError(ctxLogger, commonError.FailedPrecondition, requestID, err)
	}
	volume := &provider.Volume{}
	volume.VolumeID = volumeID

	existingVol, err := checkIfVolumeExists(session, *volume, ctxLogger)
	if existingVol == nil && err == nil {
		ctxLogger.Info("Volume not found. Returning success without deletion...")
		return &csi.DeleteVolumeResponse{}, nil
	}

	err = session.DeleteVolume(volume)
	if err != nil {
		return nil, commonError.GetCSIBackendError(ctxLogger, requestID, err)
	}
	return &csi.DeleteVolumeResponse{}, nil
}

// bmsRotatePollInterval and bmsRotatePollTimeout control how long
// getBMSServerInfo waits for an asynchronous rotate to take effect.
// VPC returns success from the rotate call immediately but only swaps in the new
// ciphertext (and sets storage_access.rotated_at) ~15s later. Variables so tests can shorten them.
var (
	bmsRotatePollInterval = 5 * time.Second
	bmsRotatePollTimeout  = 120 * time.Second
)

// getBMSServerInfo returns the host NQN and RSA-encrypted PSK for the given
// BMS serverID using a pure in-memory cache.
//
// Cache strategy (both maps keyed by serverID):
//
//	bmsCacheHostNQN  — host NQN  (nvme_qualified_name)
//	bmsCacheSecret   — encrypted PSK ciphertext
//
// Fast path: both present in cache → 0 VPC calls.
// Slow path: either absent →
//
//  1. GetBMSServer  (baseline ciphertext, before the rotate)
//  2. rotate        (asynchronous in VPC: returns success before the new secret is visible)
//  3. GetBMSServer  polled until the ciphertext differs from the baseline
//
// then populate both maps. Rotation always produces a new ciphertext (RSA
// padding is random) and the ciphertext is stable between rotations, so "ciphertext
// changed" means "rotation finished". If the rotate call itself fails (e.g. 409:
// rotated less than 1 hour ago) the baseline is used as-is; if the rotation does
// not show up within bmsRotatePollTimeout an error is returned so the attach is
// retried instead of handing the node a stale PSK.
//
// On controller restart the maps are empty → slow path on first attach per
// server.
func (csiCS *CSIControllerServer) getBMSServerInfo(ctx context.Context, ctxLogger *zap.Logger, sess provider.Session, serverID string) (string, string, error) {
	// Fast path
	if cachedNQN, cachedSecret, ok := csiCS.getCachedBMSServerInfo(serverID); ok {
		// A cache hit means NO rotate and NO fetch: whatever ciphertext was cached
		// when this controller process first attached to the server is reused. If
		// anything rotated the secret since, this value is stale.
		ctxLogger.Info("getBMSServerInfo: cache hit — 0 VPC calls, reusing cached ciphertext (not re-fetched from VPC)",
			zap.String("serverID", serverID))
		return cachedNQN, cachedSecret, nil
	}

	// Slow path: baseline fetch, rotate, then wait for the new ciphertext.
	ctxLogger.Info("getBMSServerInfo: cache miss — fetching baseline, rotating, then waiting for the new ciphertext",
		zap.String("serverID", serverID))

	// [1/3] Baseline fetch: the ciphertext as it is BEFORE we rotate.
	serverInfo, getErr := sess.GetBMSServer(serverID)
	if getErr != nil {
		return "", "", fmt.Errorf("getBMSServerInfo: GetBMSServer failed for server %s: %w", serverID, getErr)
	}
	if serverInfo == nil {
		return "", "", fmt.Errorf("getBMSServerInfo: GetBMSServer returned no data for server %s", serverID)
	}
	ctxLogger.Info("getBMSServerInfo: [1/3] baseline ciphertext fetched (pre-rotate)",
		zap.String("serverID", serverID),
		zap.Bool("encryptedSecretPresent", serverInfo.EncryptedSecret != ""))
	baselineSecret := serverInfo.EncryptedSecret

	// [2/3] Rotate, only when a key_id is configured and VPC accepts the call.
	// If the rotate is skipped or fails, the baseline (pre-rotate) ciphertext is used as-is.
	keyID := csiCS.CSIProvider.GetBMSKeyID()
	if rotateDoneAt, rotated := rotateBMSServerSecret(ctxLogger, sess, serverID, keyID); rotated {
		// [3/3] Rotation is asynchronous: wait for the new ciphertext.
		rotatedInfo, waitErr := waitForBMSRotation(ctx, ctxLogger, sess, serverID, baselineSecret, rotateDoneAt)
		if waitErr != nil {
			return "", "", waitErr
		}
		serverInfo = rotatedInfo
	}

	ctxLogger.Info("getBMSServerInfo: encrypted secret rotated and published in bm get api",
		zap.String("serverID", serverID),
		zap.Bool("differsFromBaseline", serverInfo.EncryptedSecret != baselineSecret))

	if err := validateBMSServerInfo(serverID, keyID != "", serverInfo); err != nil {
		return "", "", err
	}
	csiCS.cacheBMSServerInfo(ctxLogger, serverID, serverInfo)
	return serverInfo.HostNQN, serverInfo.EncryptedSecret, nil
}

// getCachedBMSServerInfo returns the cached host NQN and ciphertext for
// serverID. ok is true only when both are present.
func (csiCS *CSIControllerServer) getCachedBMSServerInfo(serverID string) (hostNQN, encryptedSecret string, ok bool) {
	csiCS.bmsCacheMu.RLock()
	defer csiCS.bmsCacheMu.RUnlock()
	hostNQN = csiCS.bmsCacheHostNQN[serverID]
	encryptedSecret = csiCS.bmsCacheSecret[serverID]
	return hostNQN, encryptedSecret, hostNQN != "" && encryptedSecret != ""
}

// cacheBMSServerInfo stores the host NQN and ciphertext for serverID.
func (csiCS *CSIControllerServer) cacheBMSServerInfo(ctxLogger *zap.Logger, serverID string, info *provider.BMSServerInfo) {
	csiCS.bmsCacheMu.Lock()
	csiCS.bmsCacheHostNQN[serverID] = info.HostNQN
	csiCS.bmsCacheSecret[serverID] = info.EncryptedSecret
	csiCS.bmsCacheMu.Unlock()

	ctxLogger.Info("getBMSServerInfo: cache populated (this ciphertext is reused for every later attach until the controller restarts)",
		zap.String("serverID", serverID),
		zap.String("hostNQN", info.HostNQN),
		zap.Bool("encryptedSecretPresent", info.EncryptedSecret != ""))
}

// validateBMSServerInfo checks that the server info is usable for a BMS attach.
func validateBMSServerInfo(serverID string, keyIDConfigured bool, info *provider.BMSServerInfo) error {
	// Every BMS volume connects over TLS and needs the PSK. Without a ciphertext
	// the node cannot connect, so fail the attach here instead of caching an empty
	// secret and letting nvme connect fail later with an opaque error.
	if info.EncryptedSecret == "" {
		return fmt.Errorf("getBMSServerInfo: no encrypted secret available for server %s (key_id configured: %t); cannot establish TLS connection",
			serverID, keyIDConfigured)
	}
	if info.HostNQN == "" {
		return fmt.Errorf("getBMSServerInfo: empty nvme_qualified_name (host NQN) for server %s", serverID)
	}
	return nil
}

// rotateBMSServerSecret asks VPC to re-encrypt the PSK with our public key.
// rotated is true only when VPC accepted the call, in which case the new
// ciphertext appears asynchronously and rotateDoneAt is when the call returned.
// It is false when:
//   - no keyID is configured → rotate is skipped;
//   - the rotate call fails (e.g. 409: rotated less than 1 hour ago) → the
//     current ciphertext is already encrypted with the current key.
//
// In both cases the caller keeps using the baseline ciphertext.
func rotateBMSServerSecret(ctxLogger *zap.Logger, sess provider.Session, serverID, keyID string) (rotateDoneAt time.Time, rotated bool) {
	if keyID == "" {
		ctxLogger.Warn("getBMSServerInfo: key_id is not configured — skipping rotate, using baseline ciphertext",
			zap.String("serverID", serverID))
		return time.Time{}, false
	}

	// [2/3] Rotate.
	ctxLogger.Info("getBMSServerInfo: [2/3] rotating encrypted secret — VPC will re-encrypt the PSK with our public key (asynchronous)",
		zap.String("serverID", serverID), zap.String("keyID", keyID),
		zap.Time("at", time.Now().UTC()))
	rotStart := time.Now()
	if rotErr := sess.RotateBMSEncryptedSecret(serverID, keyID); rotErr != nil {
		ctxLogger.Warn("getBMSServerInfo: [2/3] rotate failed — using baseline ciphertext",
			zap.String("serverID", serverID), zap.Duration("elapsed", time.Since(rotStart)), zap.Error(rotErr))
		return time.Time{}, false
	}
	rotateDoneAt = time.Now()
	ctxLogger.Info("getBMSServerInfo: [2/3] rotate API call succeeded — rotation is asynchronous, waiting for the ciphertext to change",
		zap.String("serverID", serverID), zap.Duration("elapsed", time.Since(rotStart)),
		zap.Time("rotateReturnedAt", rotateDoneAt.UTC()))
	return rotateDoneAt, true
}

// waitForBMSRotation polls GetBMSServer until the ciphertext is non-empty and
// differs from baselineSecret, i.e. the asynchronous rotation has finished. It
// fails if that does not happen within bmsRotatePollTimeout, or if ctx is done,
// so the attach is retried instead of handing the node a stale PSK.
func waitForBMSRotation(ctx context.Context, ctxLogger *zap.Logger, sess provider.Session, serverID, baselineSecret string, rotateDoneAt time.Time) (*provider.BMSServerInfo, error) {
	deadline := time.Now().Add(bmsRotatePollTimeout)
	for attempt := 1; ; attempt++ {
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("getBMSServerInfo: rotation for server %s was not visible after %s (ciphertext unchanged); retry the attach",
				serverID, bmsRotatePollTimeout)
		}
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("getBMSServerInfo: interrupted while waiting for rotation of server %s: %w", serverID, ctx.Err())
		case <-time.After(bmsRotatePollInterval):
		}
		polled, pollErr := sess.GetBMSServer(serverID)
		if pollErr != nil || polled == nil {
			ctxLogger.Warn("getBMSServerInfo: [3/3] poll failed, will retry",
				zap.String("serverID", serverID), zap.Int("attempt", attempt),
				zap.Bool("emptyResponse", polled == nil), zap.Error(pollErr))
			continue
		}
		changed := polled.EncryptedSecret != "" && polled.EncryptedSecret != baselineSecret
		ctxLogger.Info("getBMSServerInfo: [3/3] polled after rotate",
			zap.String("serverID", serverID), zap.Int("attempt", attempt),
			zap.Bool("ciphertextChanged", changed),
			zap.Duration("sinceRotateReturned", time.Since(rotateDoneAt)))
		if changed {
			return polled, nil
		}
	}
}

// ControllerPublishVolume ...
func (csiCS *CSIControllerServer) ControllerPublishVolume(ctx context.Context, req *csi.ControllerPublishVolumeRequest) (*csi.ControllerPublishVolumeResponse, error) {
	ctxLogger, requestID := utils.GetContextLogger(ctx, false)
	// populate requestID in the context
	ctx = context.WithValue(ctx, provider.RequestID, requestID)
	ctxLogger.Info("CSIControllerServer-ControllerPublishVolume...", zap.Reflect("Request", req))
	defer metrics.UpdateDurationFromStart(ctxLogger, metrics.FunctionLabel("ControllerPublishVolume"), time.Now())

	volumeID := req.GetVolumeId()
	if len(volumeID) == 0 {
		return nil, commonError.GetCSIError(ctxLogger, commonError.EmptyVolumeID, requestID, nil)
	}
	nodeID := req.GetNodeId()
	if len(nodeID) == 0 {
		return nil, commonError.GetCSIError(ctxLogger, commonError.EmptyNodeID, requestID, nil)
	}

	volumeCapability := req.GetVolumeCapability()
	if volumeCapability == nil {
		return nil, commonError.GetCSIError(ctxLogger, commonError.NoVolumeCapabilities, requestID, nil)
	}

	//Allow only one active attach/detach operation for an instance at anytime
	lockWaitStart := time.Now()
	csiCS.mutex.Lock(nodeID)
	defer csiCS.mutex.Unlock(nodeID)
	defer metrics.UpdateDurationFromStart(ctxLogger, metrics.FunctionLabel("ControllerPublishVolume.Lock"), lockWaitStart)

	volumeCapabilities := []*csi.VolumeCapability{volumeCapability}
	// Validate volume capabilities, are all capabilities supported by driver or not
	if !areVolumeCapabilitiesSupported(volumeCapabilities, csiCS.Driver.vcap) {
		return nil, commonError.GetCSIError(ctxLogger, commonError.VolumeCapabilitiesNotSupported, requestID, nil)
	}

	sess, err := csiCS.CSIProvider.GetProviderSession(ctx, ctxLogger)
	if err != nil {
		return nil, commonError.GetCSIError(ctxLogger, commonError.InternalError, requestID, err)
	}

	// Validate the node instance that the volume will be attached to actually exists
	// Todo Need and API to check existence of an instance being attached to via Lib
	requestedVolume := &provider.Volume{}
	requestedVolume.VolumeID = volumeID
	volDetail, err := checkIfVolumeExists(sess, *requestedVolume, ctxLogger)
	// Volume not found
	if volDetail == nil && err == nil {
		return nil, commonError.GetCSIError(ctxLogger, commonError.ObjectNotFound, requestID, nil, volumeID)
	} else if err != nil { // In case of other errors apart from volume not  found
		return nil, commonError.GetCSIError(ctxLogger, commonError.InternalError, requestID, err)
	}

	clusterID := csiCS.CSIProvider.GetClusterID()
	volumeAttachmentReq := provider.VolumeAttachmentRequest{
		VolumeID:   volumeID,
		InstanceID: nodeID,
		IKSVolumeAttachment: &provider.IKSVolumeAttachment{
			ClusterID: &clusterID,
		},
	}

	// For self-managed clusters on bare metal nodes, use the
	// BMS SDP attach path instead of the IKS/VSI path.
	if isSelfManagedCluster(clusterID) && isBaremetalNode(nodeID, ctxLogger) {
		volumeAttachmentReq.InstanceID = strings.TrimPrefix(strings.TrimPrefix(nodeID, "bms-"), "bms:")
		volumeAttachmentReq.IKSVolumeAttachment = nil
		volumeAttachmentReq.BMSVolumeAttachment = &provider.BMSVolumeAttachment{
			Protocol: "nvme_tcp",
		}
	}

	response, err := sess.AttachVolume(volumeAttachmentReq)
	if err != nil {
		// Node should be present if not return the error code
		if providerError.GetErrorType(err) == providerError.NodeNotFound {
			return nil, commonError.GetCSIError(ctxLogger, commonError.ObjectNotFound, requestID, err)
		}
		return nil, commonError.GetCSIBackendError(ctxLogger, requestID, err)
	}

	//Pass in the VPCVolumeAttachment ID for efficient retrival in WaitForAttachVolume()
	volumeAttachmentReq.VPCVolumeAttachment = &provider.VolumeAttachment{
		ID: response.VPCVolumeAttachment.ID,
	}

	response, err = sess.WaitForAttachVolume(volumeAttachmentReq)
	if err != nil {
		//retry gap is constant in the common lib i.e 10 seconds and number of retries are 4*Retry configure in the driver
		return nil, commonError.GetCSIBackendError(ctxLogger, requestID, err)
	}

	ctxLogger.Info("Attachment response", zap.Reflect("Response", response))

	// Build extra publish info — always include requestID
	extraPublishInfo := map[string]string{PublishInfoRequestID: requestID}

	// BMS path: attachment response carries BMSResponse when the volume is NVMe-oF/TCP
	if response.BMSResponse != nil && response.BMSResponse.SubsystemNQN != "" {
		// getBMSServerInfo handles rotate + GetBMSServer with in-memory caching:
		//   cache hit  → 0 VPC calls
		//   cache miss → rotate(1) + GetBMSServer(1), then populate cache
		// Use the bare server UUID (the "bms-" prefix is stripped above); the
		// VPC bare_metal_servers API does not accept the prefixed node ID.
		hostNQN, encryptedSecret, infoErr := csiCS.getBMSServerInfo(
			ctx, ctxLogger, sess, volumeAttachmentReq.InstanceID)
		if infoErr != nil {
			return nil, commonError.GetCSIError(ctxLogger, commonError.InternalError, requestID, infoErr)
		}

		extraPublishInfo[PublishInfoBMSHostNQN] = hostNQN
		extraPublishInfo[PublishInfoBMSSubsystemNQN] = response.BMSResponse.SubsystemNQN
		extraPublishInfo[PublishInfoBMSTargetIPs] = strings.Join(response.BMSResponse.TargetIPs, ",")
		if encryptedSecret != "" {
			extraPublishInfo[PublishInfoBMSEncryptedSecret] = encryptedSecret // pragma: allowlist secret
		}
		ctxLogger.Info("BMS publishContext built — this ciphertext is stored in the VolumeAttachment and handed to the node as-is",
			zap.String("subsysNQN", response.BMSResponse.SubsystemNQN),
			zap.String("hostNQN", hostNQN),
			zap.Int("targetIPs", len(response.BMSResponse.TargetIPs)),
			zap.Bool("encryptedSecretPresent", encryptedSecret != ""))
	}

	controllerPublishVolumeResponse := createControllerPublishVolumeResponse(*response, extraPublishInfo)
	return controllerPublishVolumeResponse, nil
}

// ControllerUnpublishVolume ...
func (csiCS *CSIControllerServer) ControllerUnpublishVolume(ctx context.Context, req *csi.ControllerUnpublishVolumeRequest) (*csi.ControllerUnpublishVolumeResponse, error) {
	ctxLogger, requestID := utils.GetContextLogger(ctx, false)
	// populate requestID in the context
	ctx = context.WithValue(ctx, provider.RequestID, requestID)
	defer metrics.UpdateDurationFromStart(ctxLogger, metrics.FunctionLabel("ControllerUnpublishVolume"), time.Now())
	ctxLogger.Info("CSIControllerServer-ControllerUnpublishVolume... ", zap.Reflect("Request", req))

	volumeID := req.GetVolumeId()
	if len(volumeID) == 0 {
		return nil, commonError.GetCSIError(ctxLogger, commonError.EmptyVolumeID, requestID, nil)
	}

	nodeID := req.GetNodeId()
	if len(nodeID) == 0 {
		return nil, commonError.GetCSIError(ctxLogger, commonError.EmptyNodeID, requestID, nil)
	}

	//Allow only one active attach/detach operation for an instance at anytime
	csiCS.mutex.Lock(nodeID)
	defer csiCS.mutex.Unlock(nodeID)

	clusterID := csiCS.CSIProvider.GetClusterID()
	volumeAttachmentReq := provider.VolumeAttachmentRequest{
		VolumeID:   volumeID,
		InstanceID: nodeID,
		IKSVolumeAttachment: &provider.IKSVolumeAttachment{
			ClusterID: &clusterID,
		},
	}

	// For self-managed clusters on bare metal nodes, use the
	// BMS SDP detach path instead of the IKS/VSI path.
	if isSelfManagedCluster(clusterID) && isBaremetalNode(nodeID, ctxLogger) {
		volumeAttachmentReq.InstanceID = strings.TrimPrefix(strings.TrimPrefix(nodeID, "bms-"), "bms:")
		volumeAttachmentReq.IKSVolumeAttachment = nil
		volumeAttachmentReq.BMSVolumeAttachment = &provider.BMSVolumeAttachment{
			Protocol: "nvme_tcp",
		}
	}

	sess, err := csiCS.CSIProvider.GetProviderSession(ctx, ctxLogger)
	if err != nil {
		return nil, commonError.GetCSIError(ctxLogger, commonError.InternalError, requestID, err)
	}
	response, err := sess.DetachVolume(volumeAttachmentReq)
	if err != nil {
		return nil, commonError.GetCSIBackendError(ctxLogger, requestID, err)
	}
	err = sess.WaitForDetachVolume(volumeAttachmentReq)
	if err != nil {
		//retry gap is constant in the common lib i.e 10 seconds and number of retries are 4*Retry configure in the driver
		return nil, commonError.GetCSIBackendError(ctxLogger, requestID, err)
	}
	ctxLogger.Info("Detach response", zap.Reflect("response", response))
	return &csi.ControllerUnpublishVolumeResponse{}, nil
}

// ValidateVolumeCapabilities ...
func (csiCS *CSIControllerServer) ValidateVolumeCapabilities(ctx context.Context, req *csi.ValidateVolumeCapabilitiesRequest) (*csi.ValidateVolumeCapabilitiesResponse, error) {
	ctxLogger, requestID := utils.GetContextLogger(ctx, false)
	// populate requestID in the context
	ctx = context.WithValue(ctx, provider.RequestID, requestID)
	ctxLogger.Info("CSIControllerServer-ValidateVolumeCapabilities", zap.Reflect("Request", req))

	// Validate Arguments
	if req.GetVolumeCapabilities() == nil || len(req.GetVolumeCapabilities()) == 0 {
		return nil, commonError.GetCSIError(ctxLogger, commonError.NoVolumeCapabilities, requestID, nil)
	}
	volumeID := req.GetVolumeId()
	if len(volumeID) == 0 {
		return nil, commonError.GetCSIError(ctxLogger, commonError.EmptyVolumeID, requestID, nil)
	}

	// Check if Requested Volume exists
	session, err := csiCS.CSIProvider.GetProviderSession(ctx, ctxLogger)
	if err != nil {
		return nil, commonError.GetCSIError(ctxLogger, commonError.InternalError, requestID, err)
	}

	// Get volume details by using volume ID, it should exists with provider
	_, err = session.GetVolume(volumeID)
	if err != nil {
		if providerError.RetrivalFailed == providerError.GetErrorType(err) {
			return nil, commonError.GetCSIError(ctxLogger, commonError.ObjectNotFound, requestID, err, volumeID)
		}
		return nil, commonError.GetCSIBackendError(ctxLogger, requestID, err)
	}

	// Setup Response
	var confirmed *csi.ValidateVolumeCapabilitiesResponse_Confirmed
	// Check if Volume Capabilities supported by the Driver Match
	if areVolumeCapabilitiesSupported(req.GetVolumeCapabilities(), csiCS.Driver.vcap) {
		confirmed = &csi.ValidateVolumeCapabilitiesResponse_Confirmed{VolumeCapabilities: req.GetVolumeCapabilities()}
	}

	// Return Response
	return &csi.ValidateVolumeCapabilitiesResponse{
		Confirmed: confirmed,
	}, nil
}

// ListVolumes ...
func (csiCS *CSIControllerServer) ListVolumes(ctx context.Context, req *csi.ListVolumesRequest) (*csi.ListVolumesResponse, error) {
	ctxLogger, requestID := utils.GetContextLogger(ctx, false)
	// populate requestID in the context
	ctx = context.WithValue(ctx, provider.RequestID, requestID)
	ctxLogger.Info("CSIControllerServer-ListVolumes...", zap.Reflect("Request", req))
	defer metrics.UpdateDurationFromStart(ctxLogger, metrics.FunctionLabel("ListVolumes"), time.Now())

	session, err := csiCS.CSIProvider.GetProviderSession(ctx, ctxLogger)
	if err != nil {
		return nil, commonError.GetCSIError(ctxLogger, commonError.InternalError, requestID, err)
	}

	maxEntries := int(req.MaxEntries)
	tags := map[string]string{}
	volumeList, err := session.ListVolumes(maxEntries, req.StartingToken, tags)
	if err != nil {
		errCode := err.(providerError.Message).Code
		if strings.Contains(errCode, "InvalidListVolumesLimit") {
			return nil, commonError.GetCSIError(ctxLogger, commonError.InvalidParameters, requestID, err)
		} else if strings.Contains(errCode, "StartVolumeIDNotFound") {
			return nil, commonError.GetCSIError(ctxLogger, commonError.StartVolumeIDNotFound, requestID, err, req.StartingToken)
		}
		return nil, commonError.GetCSIBackendError(ctxLogger, requestID, err)
	}

	entries := []*csi.ListVolumesResponse_Entry{}
	for _, vol := range volumeList.Volumes {
		if vol.Capacity != nil {
			entries = append(entries, &csi.ListVolumesResponse_Entry{
				Volume: &csi.Volume{
					VolumeId:      vol.VolumeID,
					CapacityBytes: int64(*vol.Capacity * utils.GiB),
				},
			})
		}
	}

	return &csi.ListVolumesResponse{
		Entries:   entries,
		NextToken: volumeList.Next,
	}, nil
}

// GetCapacity ...
func (csiCS *CSIControllerServer) GetCapacity(ctx context.Context, req *csi.GetCapacityRequest) (*csi.GetCapacityResponse, error) {
	ctxLogger, requestID := utils.GetContextLogger(ctx, false)
	// populate requestID in the context
	_ = context.WithValue(ctx, provider.RequestID, requestID)

	ctxLogger.Info("CSIControllerServer-GetCapacity", zap.Reflect("Request", req))
	return nil, commonError.GetCSIError(ctxLogger, commonError.MethodUnimplemented, requestID, nil, "GetCapacity")
}

// ControllerGetCapabilities implements the default GRPC callout.
func (csiCS *CSIControllerServer) ControllerGetCapabilities(ctx context.Context, req *csi.ControllerGetCapabilitiesRequest) (*csi.ControllerGetCapabilitiesResponse, error) {
	ctxLogger, requestID := utils.GetContextLogger(ctx, false)
	// populate requestID in the context
	_ = context.WithValue(ctx, provider.RequestID, requestID)

	ctxLogger.Info("CSIControllerServer-GetCapacity", zap.Reflect("Request", req))
	// Return the capabilities as per provider volume capabilities
	return &csi.ControllerGetCapabilitiesResponse{
		Capabilities: csiCS.Driver.cscap,
	}, nil
}

// CreateSnapshot ...
func (csiCS *CSIControllerServer) CreateSnapshot(ctx context.Context, req *csi.CreateSnapshotRequest) (*csi.CreateSnapshotResponse, error) {
	ctxLogger, requestID := utils.GetContextLogger(ctx, false)
	// populate requestID in the context
	ctx = context.WithValue(ctx, provider.RequestID, requestID)
	ctxLogger.Info("CSIControllerServer-CreateSnapshot... ", zap.Reflect("Request", req))
	defer metrics.UpdateDurationFromStart(ctxLogger, "CreateSnapshot", time.Now())

	//Feature flag to enable/disable CreateSnapshot feature.
	if strings.ToLower(os.Getenv("IS_SNAPSHOT_ENABLED")) == "false" {
		ctxLogger.Warn("CreateSnapshot functionality is disabled.")
		time.Sleep(10 * time.Minute) //To avoid multiple retries from kubernetes to CSI Driver
		return nil, commonError.GetCSIError(ctxLogger, commonError.MethodUnimplemented, requestID, nil, "CreateSnapshot functionality is disabled.")
	}

	snapshotName := req.GetName()
	if len(snapshotName) == 0 {
		return nil, commonError.GetCSIError(ctxLogger, commonError.MissingSnapshotName, requestID, nil)
	}

	sourceVolumeID := req.GetSourceVolumeId()
	if len(sourceVolumeID) == 0 {
		return nil, commonError.GetCSIError(ctxLogger, commonError.MissingSourceVolumeID, requestID, nil)
	}

	resourceGroupID := getResourceGroup(ctxLogger, req.GetParameters(), csiCS.CSIProvider.GetConfig())

	// Validate if volume Already Exists
	session, err := csiCS.CSIProvider.GetProviderSession(ctx, ctxLogger)
	if err != nil {
		if userError.GetUserErrorCode(err) == string(utilReasonCode.EndpointNotReachable) {
			return nil, commonError.GetCSIError(ctxLogger, commonError.EndpointNotReachable, requestID, err)
		}
		if userError.GetUserErrorCode(err) == string(utilReasonCode.Timeout) {
			return nil, commonError.GetCSIError(ctxLogger, commonError.Timeout, requestID, err)
		}
		return nil, commonError.GetCSIError(ctxLogger, commonError.InternalError, requestID, err)
	}

	snapshot, err := session.GetSnapshotByName(snapshotName, resourceGroupID)
	if err != nil {
		return nil, commonError.GetCSIError(ctxLogger, commonError.ListSnapshotsFailed, requestID, err)
	}

	if snapshot != nil {
		if snapshot.VolumeID != sourceVolumeID {
			return nil, commonError.GetCSIError(ctxLogger, commonError.SnapshotAlreadyExists, requestID, err, snapshotName, sourceVolumeID)
		}
		ctxLogger.Info("Snapshot with name already exist for volume", zap.Reflect("SnapshotName", snapshotName), zap.Reflect("VolumeID", sourceVolumeID))
		return createCSISnapshotResponse(*snapshot), nil
	}

	snapshotParameters := provider.SnapshotParameters{}
	snapshotParameters.Name = snapshotName
	snapshotTags := map[string]string{
		"name": snapshotName,
	}
	snapshotParameters.SnapshotTags = snapshotTags
	snapshotParameters.ResourceGroup = resourceGroupID

	snapshot, err = session.CreateSnapshot(sourceVolumeID, snapshotParameters)

	if err != nil {
		time.Sleep(time.Duration(getMaxDelaySnapshotCreate(ctxLogger)) * time.Second) //To avoid multiple retries from kubernetes to CSI Driver
		return nil, commonError.GetCSIError(ctxLogger, commonError.InternalError, requestID, err, "creation")
	}
	return createCSISnapshotResponse(*snapshot), nil
}

// DeleteSnapshot ...
func (csiCS *CSIControllerServer) DeleteSnapshot(ctx context.Context, req *csi.DeleteSnapshotRequest) (*csi.DeleteSnapshotResponse, error) {
	ctxLogger, requestID := utils.GetContextLogger(ctx, false)
	// populate requestID in the context
	ctx = context.WithValue(ctx, provider.RequestID, requestID)
	defer metrics.UpdateDurationFromStart(ctxLogger, "DeleteSnapshot", time.Now())
	ctxLogger.Info("CSIControllerServer-DeleteSnapshot... ", zap.Reflect("Request", req))

	// Validate arguments
	snapshotID := req.GetSnapshotId()
	if len(snapshotID) == 0 {
		return nil, commonError.GetCSIError(ctxLogger, commonError.EmptySnapshotID, requestID, nil)
	}

	// get the session
	session, err := csiCS.CSIProvider.GetProviderSession(ctx, ctxLogger)
	if err != nil {
		if userError.GetUserErrorCode(err) == string(utilReasonCode.EndpointNotReachable) {
			return nil, commonError.GetCSIError(ctxLogger, commonError.EndpointNotReachable, requestID, err)
		}
		if userError.GetUserErrorCode(err) == string(utilReasonCode.Timeout) {
			return nil, commonError.GetCSIError(ctxLogger, commonError.Timeout, requestID, err)
		}
		return nil, commonError.GetCSIError(ctxLogger, commonError.InternalError, requestID, err)
	}

	snapshot := &provider.Snapshot{}
	snapshot.SnapshotID, _ = getSnapshotAndAccountIDsFromCRN(snapshotID)

	err = session.DeleteSnapshot(snapshot)
	if err != nil {
		if providerError.RetrivalFailed == providerError.GetErrorType(err) {
			ctxLogger.Info("Snapshot not found. Returning success without deletion...")
			return &csi.DeleteSnapshotResponse{}, nil
		}
		return nil, commonError.GetCSIBackendError(ctxLogger, requestID, err)
	}
	return &csi.DeleteSnapshotResponse{}, nil
}

// ListSnapshots ...
func (csiCS *CSIControllerServer) ListSnapshots(ctx context.Context, req *csi.ListSnapshotsRequest) (*csi.ListSnapshotsResponse, error) {
	ctxLogger, requestID := utils.GetContextLogger(ctx, false)
	// populate requestID in the context
	ctx = context.WithValue(ctx, provider.RequestID, requestID)
	ctxLogger.Info("CSIControllerServer-ListSnapshots...", zap.Reflect("Request", req))
	defer metrics.UpdateDurationFromStart(ctxLogger, metrics.FunctionLabel("ListSnapshots"), time.Now())

	session, err := csiCS.CSIProvider.GetProviderSession(ctx, ctxLogger)
	if err != nil {
		if userError.GetUserErrorCode(err) == string(utilReasonCode.EndpointNotReachable) {
			return nil, commonError.GetCSIError(ctxLogger, commonError.EndpointNotReachable, requestID, err)
		}
		if userError.GetUserErrorCode(err) == string(utilReasonCode.Timeout) {
			return nil, commonError.GetCSIError(ctxLogger, commonError.Timeout, requestID, err)
		}
		return nil, commonError.GetCSIError(ctxLogger, commonError.InternalError, requestID, err)
	}

	entries := []*csi.ListSnapshotsResponse_Entry{}
	snapshotID := req.GetSnapshotId()
	snapID, snapshotAccountID := getSnapshotAndAccountIDsFromCRN(snapshotID)
	if len(snapID) != 0 {
		if csiCS.Driver.accountID == snapshotAccountID { // in case snapshotID's account and cluster account ID is same
			snapshot, err := session.GetSnapshot(snapID)
			if snapshot == nil {
				return &csi.ListSnapshotsResponse{}, nil
			}
			if providerError.RetrivalFailed == providerError.GetErrorType(err) {
				ctxLogger.Info("Snapshot not found. Returning success ...")
				return &csi.ListSnapshotsResponse{}, nil
			}
			return &csi.ListSnapshotsResponse{
				Entries: append(entries, &csi.ListSnapshotsResponse_Entry{
					Snapshot: createCSISnapshotResponse(*snapshot).Snapshot,
				}),
				NextToken: "",
			}, nil
		} else { // In case of cross account volume snapshot
			return &csi.ListSnapshotsResponse{
				Entries: append(entries, &csi.ListSnapshotsResponse_Entry{
					Snapshot: &csi.Snapshot{
						SnapshotId:     snapshotID,
						SourceVolumeId: "",
						ReadyToUse:     true,
					},
				}),
				NextToken: "",
			}, nil
		}

	}

	maxEntries := int(req.GetMaxEntries())
	tags := map[string]string{}
	sourceVolumeID := req.GetSourceVolumeId()
	if len(sourceVolumeID) != 0 {
		tags["source_volume.id"] = sourceVolumeID
	}
	snapshotList, err := session.ListSnapshots(maxEntries, req.StartingToken, tags)
	if err != nil {
		errCode := err.(providerError.Message).Code
		if strings.Contains(errCode, "InvalidListSnapshotLimit") {
			return nil, commonError.GetCSIError(ctxLogger, commonError.InvalidParameters, requestID, err)
		} else if strings.Contains(errCode, "StartSnapshotIDNotFound") {
			return nil, commonError.GetCSIError(ctxLogger, commonError.StartSnapshotIDNotFound, requestID, err, req.StartingToken)
		}
		return nil, commonError.GetCSIError(ctxLogger, commonError.ListSnapshotsFailed, requestID, err)
	}

	for _, snap := range snapshotList.Snapshots {
		snapObj := createCSISnapshotResponse(*snap)
		entries = append(entries, &csi.ListSnapshotsResponse_Entry{
			Snapshot: snapObj.Snapshot,
		})
	}

	return &csi.ListSnapshotsResponse{
		Entries:   entries,
		NextToken: snapshotList.Next,
	}, nil
}

// getSnapshots ...
func (csiCS *CSIControllerServer) getSnapshots(ctx context.Context, req *csi.ListSnapshotsRequest) (*csi.ListSnapshotsResponse, error) {
	ctxLogger, requestID := utils.GetContextLogger(ctx, false)
	// populate requestID in the context
	_ = context.WithValue(ctx, provider.RequestID, requestID)

	ctxLogger.Info("CSIControllerServer-getSnapshots", zap.Reflect("Request", req))
	return nil, commonError.GetCSIError(ctxLogger, commonError.MethodUnimplemented, requestID, nil, "getSnapshots")
}

// getSnapshotById ...
func (csiCS *CSIControllerServer) getSnapshotByID(ctx context.Context, snapshotID string) (*csi.ListSnapshotsResponse, error) {
	ctxLogger, requestID := utils.GetContextLogger(ctx, false)
	// populate requestID in the context
	_ = context.WithValue(ctx, provider.RequestID, requestID)

	ctxLogger.Info("CSIControllerServer-getSnapshotByID", zap.Reflect("Request", snapshotID))
	return nil, commonError.GetCSIError(ctxLogger, commonError.MethodUnimplemented, requestID, nil, "getSnapshotByID")
}

// ControllerExpandVolume ...
func (csiCS *CSIControllerServer) ControllerExpandVolume(ctx context.Context, req *csi.ControllerExpandVolumeRequest) (*csi.ControllerExpandVolumeResponse, error) {
	ctxLogger, requestID := utils.GetContextLogger(ctx, false)
	// populate requestID in the context
	_ = context.WithValue(ctx, provider.RequestID, requestID)
	defer metrics.UpdateDurationFromStart(ctxLogger, "ControllerExpandVolume", time.Now())
	ctxLogger.Info("CSIControllerServer-ControllerExpandVolume", zap.Reflect("Request", req))
	volumeID := req.GetVolumeId()
	capacity := req.GetCapacityRange().GetRequiredBytes()
	if len(volumeID) == 0 {
		return nil, commonError.GetCSIError(ctxLogger, commonError.EmptyVolumeID, requestID, nil)
	}

	// get the session
	session, err := csiCS.CSIProvider.GetProviderSession(ctx, ctxLogger)
	if err != nil {
		return nil, commonError.GetCSIError(ctxLogger, commonError.FailedPrecondition, requestID, err)
	}
	requestedVolume := &provider.Volume{}
	requestedVolume.VolumeID = volumeID
	volDetail, err := checkIfVolumeExists(session, *requestedVolume, ctxLogger)
	// Volume not found
	if volDetail == nil && err == nil {
		return nil, commonError.GetCSIError(ctxLogger, commonError.ObjectNotFound, requestID, nil, volumeID)
	} else if err != nil { // In case of other errors apart from volume not found
		return nil, commonError.GetCSIError(ctxLogger, commonError.InternalError, requestID, err)
	}

	volumeExpansionReq := provider.ExpandVolumeRequest{
		VolumeID: volumeID,
		Capacity: capacity,
	}
	_, err = session.ExpandVolume(volumeExpansionReq)
	if err != nil {
		return nil, commonError.GetCSIBackendError(ctxLogger, requestID, err)
	}

	// Raw block volumes have no filesystem; node-side expansion is not needed.
	// VolumeCapability is optional in the CSI spec; default to requiring node expansion
	// when it is not set so that filesystem volumes are handled correctly.
	nodeExpansionRequired := true
	if vc := req.GetVolumeCapability(); vc != nil {
		if _, ok := vc.GetAccessType().(*csi.VolumeCapability_Block); ok {
			nodeExpansionRequired = false
			ctxLogger.Info("CSIControllerServer-ControllerExpandVolume: raw block volume detected, skipping node expansion", zap.String("volumeID", volumeID))
		}
	}
	return &csi.ControllerExpandVolumeResponse{CapacityBytes: capacity, NodeExpansionRequired: nodeExpansionRequired}, nil
}

// ControllerGetVolume ...
func (csiCS *CSIControllerServer) ControllerGetVolume(ctx context.Context, req *csi.ControllerGetVolumeRequest) (*csi.ControllerGetVolumeResponse, error) {
	ctxLogger, requestID := utils.GetContextLogger(ctx, false)
	return nil, commonError.GetCSIError(ctxLogger, commonError.MethodUnimplemented, requestID, nil, "ControllerGetVolume")
}

// ControllerModifyVolume ...
func (csiCS *CSIControllerServer) ControllerModifyVolume(ctx context.Context, req *csi.ControllerModifyVolumeRequest) (*csi.ControllerModifyVolumeResponse, error) {
	ctxLogger, requestID := utils.GetContextLogger(ctx, false)
	return nil, commonError.GetCSIError(ctxLogger, commonError.MethodUnimplemented, requestID, nil, "ControllerModifyVolume")
}
