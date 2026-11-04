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

// Package riaas ...
package riaas

import (
	"context"
	"net/url"
	"strconv"

	"github.com/IBM/ibmcloud-volume-vpc/common/vpcclient/client"
	"github.com/IBM/ibmcloud-volume-vpc/common/vpcclient/models"
)

// newBaseClient creates the client shared by all the profiles of a session.
// It carries only the profile-neutral values (generation, headers, debug
// writer); the API version is added per profile by newClient.
func newBaseClient(config Config) client.SessionClient {
	ctx := config.Context
	if ctx == nil {
		ctx = context.Background()
	}

	// Default API generation, overwritten if the generation is passed
	apiGen := models.APIGeneration
	if config.APIGeneration > 0 {
		apiGen = config.APIGeneration
	}

	queryValues := url.Values{
		"generation": []string{strconv.Itoa(apiGen)},
	}

	baseClient := client.New(ctx, config.baseURL(), queryValues, config.httpClient(), config.ContextID, config.ResourceGroup)
	if config.DebugWriter != nil {
		baseClient.WithDebug(config.DebugWriter)
	}
	return baseClient
}

// newClient returns a client for the given profile, backed by base.
// BMS gets its own query values, every other profile gets the configured API version.
func newClient(base client.SessionClient, profile apiProfile, config Config) client.SessionClient {
	if profile == profileBMS {
		return &bmsClient{base}
	}

	// Default API version, overwritten if the version is passed
	apiVersion := models.APIVersion
	if len(config.APIVersion) > 0 {
		apiVersion = config.APIVersion
	}
	return &vpcClient{SessionClient: base, apiVersion: apiVersion}
}
