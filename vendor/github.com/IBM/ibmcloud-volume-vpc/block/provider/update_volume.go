/**
 * Copyright 2020 IBM Corp.
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

// Package provider ...
package provider

import (
	"github.com/IBM/ibmcloud-volume-interface/lib/provider"
	userError "github.com/IBM/ibmcloud-volume-vpc/common/messages"
	"github.com/IBM/ibmcloud-volume-vpc/common/vpcclient/models"
	"go.uber.org/zap"
)

// UpdateVolume POSTs to /volumes
func (vpc *VPCSession) UpdateVolume(volumeRequest provider.Volume) error {

	// Get volume details
	existVolume, err := vpc.GetVolume(volumeRequest.VolumeID)
	if err != nil {
		return userError.GetUserError("UpdateVolumeWithTagsFailed", err)
	}

	volumeRequest.VPCVolume.Tags = append(volumeRequest.VPCVolume.Tags, existVolume.Tags...)

	volume := models.Volume{
		ID:   volumeRequest.VolumeID,
		Tags: volumeRequest.VPCVolume.Tags,
		ETag: existVolume.ETag,
	}

	vpc.Logger.Info("Successfully validated inputs for UpdateVolumeWithTagsFailed request... ")

	vpc.Logger.Info("Calling VPC provider for volume UpdateVolumeWithTagsFailed...")

	err = retry(vpc.Logger, func() error {
		err = vpc.Apiclient.VolumeService().UpdateVolume(&volume, vpc.Logger)
		return err
	})

	if err != nil {
		vpc.Logger.Debug("Failed to update volume with tags from VPC provider", zap.Reflect("BackendError", err))
		return userError.GetUserError("FailedToUpdateVolume", err, volumeRequest.VolumeID)
	}

	return err
}
