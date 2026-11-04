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
	"time"

	"github.com/IBM/ibmcloud-volume-vpc/common/vpcclient/client"
)

// bmsClient overrides the query values of every request: the API version is
// the current date and maturity=development. Everything else is delegated to
// the embedded client.
type bmsClient struct {
	client.SessionClient
}

// NewRequest creates the request using the embedded client and then overrides
// its query values for BMS calls:
//   - version:  today's date (UTC, YYYY-MM-DD) instead of the configured API
//     version. It is computed on every call, so a long-running session never
//     sends a stale date.
//   - maturity: "development", as required by the BMS API.
//
// Any other query value (for example generation), the headers, the auth token
// and the debug writer are inherited from the embedded client unchanged. The
// override is applied only to the returned request, so the embedded client and
// the other services that share it are not affected.
func (b *bmsClient) NewRequest(operation *client.Operation) *client.Request {
	return b.SessionClient.NewRequest(operation).
		SetQueryValue("version", time.Now().UTC().Format(time.DateOnly)).
		SetQueryValue("maturity", "development")
}

// WithQueryValue adds the query value to the embedded client and keeps this
// client, so that chained calls such as vs.client = vs.client.WithQueryValue()
// do not drop the BMS query values.
func (b *bmsClient) WithQueryValue(name, value string) client.SessionClient {
	b.SessionClient.WithQueryValue(name, value)
	return b
}
