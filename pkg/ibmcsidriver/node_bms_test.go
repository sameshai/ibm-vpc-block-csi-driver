/**
 * Copyright 2025 IBM Corp.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package ibmcsidriver

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"reflect"
	"testing"

	"go.uber.org/zap"
)

func TestDecryptBMSSecret(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	psk := "NVMeTLSkey-1:01:dGVzdA==:"

	oaep, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, &key.PublicKey, []byte(psk), nil)
	if err != nil {
		t.Fatal(err)
	}
	pkcs, err := rsa.EncryptPKCS1v15(rand.Reader, &key.PublicKey, []byte(psk))
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		cipher  string
		wantErr bool
	}{
		{"OAEP-SHA256", base64.StdEncoding.EncodeToString(oaep), false},
		{"PKCS1v15", base64.StdEncoding.EncodeToString(pkcs), false},
		{"garbage", base64.StdEncoding.EncodeToString(make([]byte, 256)), true},
		{"bad base64", "!!!", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := decryptBMSSecret(keyPEM, tc.cipher)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
			if !tc.wantErr && got != psk {
				t.Fatalf("got %q, want %q", got, psk)
			}
		})
	}
}

func TestBMSDevicePathCandidates(t *testing.T) {
	const uuid = "342f4b28-b6f0-4b23-b9c5-0cdf036f4948"
	tests := []struct {
		name     string
		volumeID string
		want     []string
	}{
		{"r134 prefix", "r134-" + uuid, []string{bmsDevicePathPrefix + uuid, bmsDevicePathPrefix + "r134-" + uuid}},
		{"other prefix length", "r006-" + uuid, []string{bmsDevicePathPrefix + uuid, bmsDevicePathPrefix + "r006-" + uuid}},
		{"bare uuid", uuid, []string{bmsDevicePathPrefix + uuid}},
		{"short id", "vol-1", []string{bmsDevicePathPrefix + "vol-1"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := bmsDevicePathCandidates(tc.volumeID)
			if len(got) != len(tc.want) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("got %v, want %v", got, tc.want)
				}
			}
		})
	}
}

func TestIsNVMeAlreadyConnected(t *testing.T) {
	assert := func(out string, want bool) {
		t.Helper()
		if got := isNVMeAlreadyConnected(out); got != want {
			t.Fatalf("isNVMeAlreadyConnected(%q) = %v, want %v", out, got, want)
		}
	}
	assert("already connected\n", true)
	assert("Already Connected", true)
	assert("Failed to write to /dev/nvme-fabrics: Permission denied\n", false)
	assert("", false)
}

// nvmeConnect must try every target IP: a volume's namespace is accessible
// through only some of them, so stopping at the first success leaves volumes
// without a device.
func TestNvmeConnect_ConnectsAllIPs(t *testing.T) {
	old := nvmeRun
	t.Cleanup(func() { nvmeRun = old })

	cases := []struct {
		name      string
		ips       string
		results   map[string]error // by IP; nil = success
		outputs   map[string]string
		wantIPs   []string
		wantError bool
	}{
		{
			name:    "all succeed",
			ips:     "10.0.0.1,10.0.0.2,10.0.0.3,10.0.0.4",
			wantIPs: []string{"10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"},
		},
		{
			name:    "already connected counts as connected and does not stop the loop",
			ips:     "10.0.0.1,10.0.0.2,10.0.0.3",
			results: map[string]error{"10.0.0.1": errors.New("exit status 1")},
			outputs: map[string]string{"10.0.0.1": "already connected\n"},
			wantIPs: []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"},
		},
		{
			name:    "one failure is tolerated",
			ips:     "10.0.0.1,10.0.0.2,10.0.0.3",
			results: map[string]error{"10.0.0.2": errors.New("exit status 1")},
			outputs: map[string]string{"10.0.0.2": "Permission denied"},
			wantIPs: []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"},
		},
		{
			name: "all fail",
			ips:  "10.0.0.1,10.0.0.2",
			results: map[string]error{
				"10.0.0.1": errors.New("exit status 1"),
				"10.0.0.2": errors.New("exit status 1"),
			},
			wantIPs:   []string{"10.0.0.1", "10.0.0.2"},
			wantError: true,
		},
		{
			name:    "blank entries and spaces are skipped",
			ips:     " 10.0.0.1 , ,10.0.0.2",
			wantIPs: []string{"10.0.0.1", "10.0.0.2"},
		},
		{name: "no IPs", ips: "", wantError: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var called []string
			nvmeRun = func(args ...string) ([]byte, error) {
				var ip string
				for i, a := range args {
					if a == "--traddr" {
						ip = args[i+1]
					}
				}
				called = append(called, ip)
				return []byte(tc.outputs[ip]), tc.results[ip]
			}
			err := nvmeConnect(zap.NewNop(), "hostnqn", "subsysnqn", tc.ips)
			if (err != nil) != tc.wantError {
				t.Fatalf("err = %v, wantError %v", err, tc.wantError)
			}
			if !reflect.DeepEqual(called, tc.wantIPs) {
				t.Fatalf("connected IPs = %v, want %v", called, tc.wantIPs)
			}
		})
	}
}
