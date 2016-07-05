/*
 * Copyright (c) 2014-2015 VMware, Inc. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License.  You may obtain a copy of
 * the License at http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed
 * under the License is distributed on an "AS IS" BASIS, without warranties or
 * conditions of any kind, EITHER EXPRESS OR IMPLIED.  See the License for the
 * specific language governing permissions and limitations under the License.
 */

package com.vmware.xenon.common;

import java.util.Set;

public class ClaimsVerificationState extends ServiceDocument {
    /**
     * This service document is used when we request external authentication
     * providers to provide claims data. The response from external auth providers
     * will be a ClaimsVerificationState document
     */
    public String issuer;
    public String subject;
    public Set<String> audience;
    public Long expirationTime;
    public Long notBefore;
    public Long issuedAt;
    public String jwtId;
}