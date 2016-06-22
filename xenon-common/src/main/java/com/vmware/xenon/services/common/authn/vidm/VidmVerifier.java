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

package com.vmware.xenon.services.common.authn.vidm;

import java.nio.charset.Charset;
import java.security.GeneralSecurityException;
import java.util.Base64;
import java.util.HashSet;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import com.vmware.horizon.common.api.token.SuiteToken;
import com.vmware.horizon.common.api.token.SuiteTokenConfiguration;
import com.vmware.horizon.common.api.token.SuiteTokenException;
import com.vmware.xenon.common.Claims;
import com.vmware.xenon.common.jwt.Rfc7519Claims;

public class VidmVerifier {

    protected Base64.Decoder decoder = Base64.getUrlDecoder();
    protected Gson gson;
    private static final String hostName = "https://blr-2nd-1-dhcp666.eng.vmware.com" ;

    public VidmVerifier() {
        this.gson = new GsonBuilder().create();
    }

    public <T extends Rfc7519Claims> Claims verify(String jwt , String userLink) throws VidmTokenException,
            GeneralSecurityException {

        //Extract current token , create a claim object , return that
        SuiteToken suiteToken = getSuiteTokenObject(jwt);

        Claims.Builder builder = new Claims.Builder();
        builder.setIssuer(suiteToken.getIssuer());
        builder.setSubject(userLink);
        builder.setExpirationTime(suiteToken.getExpires() * 1000000);

        HashSet<String> audienceSet = new HashSet<String>();
        audienceSet.add(suiteToken.getAudience());
        builder.setAudience(audienceSet);

        Claims claims = builder.getResult();
        return claims;
    }

    private SuiteToken getSuiteTokenObject(String token) throws VidmTokenException {
        SuiteTokenConfiguration s = new SuiteTokenConfiguration();
        s.setPublicKeyUrl(hostName + "/SAAS/API/1.0/REST/auth/token?attribute=publicKey");
        s.setRevokeCheckUrl(hostName + "/SAAS/API/1.0/REST/auth/token?attribute=isRevoked");

        SuiteToken suiteToken = null ;
        try {
            suiteToken = SuiteToken.decodeSuiteToken(token);
        } catch (SuiteTokenException e) {
            throw new VidmTokenException("Unable to decode the suite Token");
        }
        return suiteToken ;
    }

    public static class VidmTokenException extends Exception {
        private static final long serialVersionUID = 1640724864336370401L;

        VidmTokenException(String message) {
            super(message);
        }
    }

    protected byte[] decode(String payload) {
        return this.decoder.decode(payload.getBytes(Charset.forName("UTF-8")));
    }

    protected <T> T decode(String payload, Class<T> klass) {
        String json = new String(decode(payload), Charset.forName("UTF-8"));
        return this.gson.fromJson(json, klass);
    }
}

