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

package com.vmware.xenon.authn.vidm;

import com.vmware.horizon.common.api.token.SuiteToken;
import com.vmware.horizon.common.api.token.SuiteTokenConfiguration;
import com.vmware.horizon.common.api.token.SuiteTokenException;

public class VidmUtils {

    protected static SuiteToken getSuiteTokenObject(String token) throws VidmTokenException {
        SuiteTokenConfiguration s = new SuiteTokenConfiguration();
        s.setPublicKeyUrl(VidmProperties.getHostName() +
                "/SAAS/API/1.0/REST/auth/token?attribute=publicKey");
        s.setRevokeCheckUrl(VidmProperties.getHostName() +
                "/SAAS/API/1.0/REST/auth/token?attribute=isRevoked");

        SuiteToken suiteToken = null ;
        try {
            suiteToken = SuiteToken.decodeSuiteToken(token);
        } catch (SuiteTokenException e) {
            throw new VidmTokenException("Invalid vIDM Token");
        }
        return suiteToken ;
    }

    public static class VidmTokenException extends Exception {
        private static final long serialVersionUID = 1640724864336370401L;

        VidmTokenException(String message) {
            super(message);
        }
    }
}
