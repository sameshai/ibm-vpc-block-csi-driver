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
	"context"
	"errors"
	"testing"
	"time"

	"github.com/IBM/ibmcloud-volume-interface/lib/provider"
	"github.com/IBM/ibmcloud-volume-interface/lib/provider/fake"
	cloudProvider "github.com/IBM/ibmcloud-volume-vpc/pkg/ibmcloudprovider"
	"github.com/stretchr/testify/assert"
)

// bmsKeyProvider wraps the fake provider so GetBMSKeyID returns a non-empty
// key ID (the stock fake returns "", which skips the rotate path).
type bmsKeyProvider struct {
	cloudProvider.CloudProviderInterface
}

func (bmsKeyProvider) GetBMSKeyID() string { return "test-key-id" }

func newBMSTestController(t *testing.T) *CSIControllerServer {
	t.Helper()
	prov, err := cloudProvider.NewFakeIBMCloudStorageProvider("", nil)
	if err != nil {
		t.Fatalf("fake provider: %v", err)
	}
	cs := NewControllerServer(nil, bmsKeyProvider{prov})
	return cs
}

func shortBMSPolling(t *testing.T, interval, timeout time.Duration) {
	t.Helper()
	oldI, oldT := bmsRotatePollInterval, bmsRotatePollTimeout
	bmsRotatePollInterval, bmsRotatePollTimeout = interval, timeout
	t.Cleanup(func() { bmsRotatePollInterval, bmsRotatePollTimeout = oldI, oldT })
}

// Rotation is asynchronous: GETs right after the rotate still return the old
// ciphertext. getBMSServerInfo must keep polling until it changes.
func TestGetBMSServerInfo_WaitsForAsyncRotation(t *testing.T) {
	logger, teardown := cloudProvider.GetTestLogger(t)
	defer teardown()
	shortBMSPolling(t, 5*time.Millisecond, 2*time.Second)

	cs := newBMSTestController(t)
	sess := &fake.FakeSession{}
	gets := 0
	sess.GetBMSServerStub = func(string) (*provider.BMSServerInfo, error) {
		gets++
		secret := "OLD"
		if gets >= 4 { // baseline + 2 stale polls, then the rotation lands
			secret = "NEW"
		}
		return &provider.BMSServerInfo{HostNQN: "nqn.host", EncryptedSecret: secret}, nil
	}

	nqn, secret, err := cs.getBMSServerInfo(context.Background(), logger, sess, "srv")
	assert.NoError(t, err)
	assert.Equal(t, "nqn.host", nqn)
	assert.Equal(t, "NEW", secret, "must return the post-rotation ciphertext, not the stale one")
	assert.Equal(t, 1, sess.RotateBMSEncryptedSecretCallCount())
	assert.Equal(t, 4, gets)

	// Second call is a cache hit: no more VPC calls.
	_, secret, err = cs.getBMSServerInfo(context.Background(), logger, sess, "srv")
	assert.NoError(t, err)
	assert.Equal(t, "NEW", secret)
	assert.Equal(t, 1, sess.RotateBMSEncryptedSecretCallCount())
	assert.Equal(t, 4, gets)
}

// If the rotate call fails (e.g. 409, rotated < 1h ago) the current ciphertext
// is used immediately instead of waiting for a change that will never come.
func TestGetBMSServerInfo_RotateFailsUsesBaseline(t *testing.T) {
	logger, teardown := cloudProvider.GetTestLogger(t)
	defer teardown()
	shortBMSPolling(t, 5*time.Millisecond, 100*time.Millisecond)

	cs := newBMSTestController(t)
	sess := &fake.FakeSession{}
	sess.RotateBMSEncryptedSecretReturns(errors.New("409 conflict_state"))
	sess.GetBMSServerReturns(&provider.BMSServerInfo{HostNQN: "nqn.host", EncryptedSecret: "CURRENT"}, nil)

	_, secret, err := cs.getBMSServerInfo(context.Background(), logger, sess, "srv")
	assert.NoError(t, err)
	assert.Equal(t, "CURRENT", secret)
	assert.Equal(t, 1, sess.GetBMSServerCallCount(), "no polling after a failed rotate")
}

// If the rotation never becomes visible, fail the attach (kubelet/attacher
// retries) rather than hand the node a stale PSK, and do not cache anything.
func TestGetBMSServerInfo_RotationNeverVisibleFails(t *testing.T) {
	logger, teardown := cloudProvider.GetTestLogger(t)
	defer teardown()
	shortBMSPolling(t, 5*time.Millisecond, 50*time.Millisecond)

	cs := newBMSTestController(t)
	sess := &fake.FakeSession{}
	sess.GetBMSServerReturns(&provider.BMSServerInfo{HostNQN: "nqn.host", EncryptedSecret: "OLD"}, nil)

	_, _, err := cs.getBMSServerInfo(context.Background(), logger, sess, "srv")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not visible")
	assert.Empty(t, cs.bmsCacheSecret["srv"], "a stale secret must not be cached")
}

// No key_id configured (rotate skipped) and the server has no ciphertext: the
// node could never connect over TLS, so fail the attach and cache nothing.
func TestGetBMSServerInfo_NoKeyIDAndEmptySecretFails(t *testing.T) {
	logger, teardown := cloudProvider.GetTestLogger(t)
	defer teardown()

	prov, err := cloudProvider.NewFakeIBMCloudStorageProvider("", nil)
	assert.NoError(t, err)
	cs := NewControllerServer(nil, prov) // stock fake: GetBMSKeyID() == ""
	sess := &fake.FakeSession{}
	sess.GetBMSServerReturns(&provider.BMSServerInfo{HostNQN: "nqn.host", EncryptedSecret: ""}, nil)

	_, _, err = cs.getBMSServerInfo(context.Background(), logger, sess, "srv")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no encrypted secret")
	assert.Equal(t, 0, sess.RotateBMSEncryptedSecretCallCount(), "rotate must be skipped without a key_id")
	assert.Empty(t, cs.bmsCacheHostNQN["srv"], "nothing must be cached")
	assert.Empty(t, cs.bmsCacheSecret["srv"], "nothing must be cached")
}

// Rotate fails (e.g. 409) and the baseline is empty: nothing to fall back to.
func TestGetBMSServerInfo_RotateFailsAndEmptySecretFails(t *testing.T) {
	logger, teardown := cloudProvider.GetTestLogger(t)
	defer teardown()
	shortBMSPolling(t, 5*time.Millisecond, 100*time.Millisecond)

	cs := newBMSTestController(t)
	sess := &fake.FakeSession{}
	sess.RotateBMSEncryptedSecretReturns(errors.New("409 conflict_state"))
	sess.GetBMSServerReturns(&provider.BMSServerInfo{HostNQN: "nqn.host", EncryptedSecret: ""}, nil)

	_, _, err := cs.getBMSServerInfo(context.Background(), logger, sess, "srv")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no encrypted secret")
	assert.Empty(t, cs.bmsCacheSecret["srv"], "nothing must be cached")
}
