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

import java.security.GeneralSecurityException;
import java.util.HashSet;

import com.vmware.horizon.common.api.token.SuiteToken;
import com.vmware.horizon.common.api.token.SuiteTokenConfiguration;
import com.vmware.horizon.common.api.token.SuiteTokenException;
import com.vmware.xenon.authn.common.VerifierService;
import com.vmware.xenon.common.Claims;
import com.vmware.xenon.common.ClaimsVerificationState;
import com.vmware.xenon.services.common.ServiceUriPaths;

public class VidmVerifierService extends VerifierService {

    public static String SELF_LINK = ServiceUriPaths.CORE_AUTHN_VERIFY_VIDM;

    private final String hostName = VidmProperties.getHostName() ;
    private String userLink ;

    public ClaimsVerificationState verify(String token) throws VidmTokenException,
            GeneralSecurityException {

        this.userLink = VidmProperties.getVidmUserLink();

        if (this.hostName == null || this.userLink == null) {
            throw new GeneralSecurityException("Invalid vIDM configuration details");
        }
        SuiteToken suiteToken = getSuiteTokenObject(token);

        Claims.Builder builder = new Claims.Builder();
        builder.setIssuer(suiteToken.getIssuer());
        builder.setSubject(this.userLink);
        builder.setExpirationTime(suiteToken.getExpires() * 1000000);

        HashSet<String> audienceSet = new HashSet<String>();
        audienceSet.add(suiteToken.getAudience());
        builder.setAudience(audienceSet);

        Claims claims = builder.getResult();

        ClaimsVerificationState claimsVerificationState = new ClaimsVerificationState();

        claimsVerificationState.audience = new HashSet<>(claims.getAudience());
        claimsVerificationState.expirationTime = claims.getExpirationTime();
        claimsVerificationState.issuedAt = claims.getIssuedAt();
        claimsVerificationState.issuer = claims.getIssuer();
        claimsVerificationState.jwtId = claims.getJwtId();
        claimsVerificationState.notBefore = claims.getNotBefore();
        claimsVerificationState.subject = claims.getSubject();

        return claimsVerificationState;
    }

    private SuiteToken getSuiteTokenObject(String token) throws VidmTokenException {
        SuiteTokenConfiguration s = new SuiteTokenConfiguration();
        s.setPublicKeyUrl(this.hostName + "/SAAS/API/1.0/REST/auth/token?attribute=publicKey");
        s.setRevokeCheckUrl(this.hostName + "/SAAS/API/1.0/REST/auth/token?attribute=isRevoked");

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

