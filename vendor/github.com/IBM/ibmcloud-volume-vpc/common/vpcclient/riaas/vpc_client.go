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
	"github.com/IBM/ibmcloud-volume-vpc/common/vpcclient/client"
)

// vpcClient adds the configured API version to every request. It is used by
// all the profiles other than BMS. Everything else is delegated to the
// embedded client.
type vpcClient struct {
	client.SessionClient
	apiVersion string
}

// NewRequest creates the request using the embedded client and sets its API version.
func (v *vpcClient) NewRequest(operation *client.Operation) *client.Request {
	return v.SessionClient.NewRequest(operation).
		SetQueryValue("version", v.apiVersion)
}

// WithQueryValue adds the query value to the embedded client and keeps this
// client, so that chained calls such as vs.client = vs.client.WithQueryValue()
// do not drop the API version.
func (v *vpcClient) WithQueryValue(name, value string) client.SessionClient {
	v.SessionClient.WithQueryValue(name, value)
	return v
}
