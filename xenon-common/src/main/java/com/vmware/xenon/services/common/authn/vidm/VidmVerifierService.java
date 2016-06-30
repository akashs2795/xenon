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

import java.security.GeneralSecurityException;
import java.util.HashSet;

import com.vmware.horizon.common.api.token.SuiteToken;
import com.vmware.horizon.common.api.token.SuiteTokenConfiguration;
import com.vmware.horizon.common.api.token.SuiteTokenException;
import com.vmware.xenon.common.Claims;
import com.vmware.xenon.common.ClaimsVerificationState;
import com.vmware.xenon.common.Operation;
import com.vmware.xenon.common.ServiceDocument;
import com.vmware.xenon.common.StatelessService;
import com.vmware.xenon.common.Utils;
import com.vmware.xenon.services.common.QueryTask;
import com.vmware.xenon.services.common.ServiceUriPaths;
import com.vmware.xenon.services.common.UserService;


public class VidmVerifierService extends StatelessService {

    public static String SELF_LINK = ServiceUriPaths.CORE_AUTHN_VERIFY_VIDM;

    private static final String hostName = "https://blr-2nd-1-dhcp666.eng.vmware.com" ;
    protected String userLink ;

    @Override
    public void authorizeRequest(Operation op) {
        op.complete();
    }

    @Override
    public void handlePost(Operation op) {
        System.out.println("\n\nVIDM-VERIFIER\nHandling POST");
        handleVerification(op);
    }

    public void handleVerification(Operation parentOp) {
        System.out.println("Handling Verification");
        String token = parentOp.getRequestHeader("token");
        System.out.println("Token : " + token);
        queryUserService(parentOp);
        ClaimsVerificationState claimsDocument;
        try {
            claimsDocument = verify(token, this.userLink);
        } catch (VidmTokenException | GeneralSecurityException e) {
            System.out.println("Some exception ! ");
            parentOp.fail(Operation.STATUS_CODE_NOT_FOUND);
            return ;
        }
        parentOp.setStatusCode(Operation.STATUS_CODE_OK);
        parentOp.setBodyNoCloning(claimsDocument).complete();
        return ;
    }

    private void queryUserService(Operation parentOp) {
        System.out.println("Querying user Service.");
        QueryTask q = new QueryTask();
        q.querySpec = new QueryTask.QuerySpecification();

        String kind = Utils.buildKind(UserService.UserState.class);
        QueryTask.Query kindClause = new QueryTask.Query()
                .setTermPropertyName(ServiceDocument.FIELD_NAME_KIND)
                .setTermMatchValue(kind);
        q.querySpec.query.addBooleanClause(kindClause);

        QueryTask.Query emailClause = new QueryTask.Query()
                .setTermPropertyName(UserService.UserState.FIELD_NAME_EMAIL)
                .setTermMatchValue(VidmProperties.VIDM_USER);
        emailClause.occurance = QueryTask.Query.Occurance.MUST_OCCUR;

        q.querySpec.query.addBooleanClause(emailClause);
        q.taskInfo.isDirect = true;

        Operation.CompletionHandler userServiceCompletion = (o, ex) -> {
            if (ex != null) {
                logWarning("Exception validating user: %s", Utils.toString(ex));
                parentOp.setBodyNoCloning(o.getBodyRaw()).fail(o.getStatusCode());
                return;
            }

            QueryTask rsp = o.getBody(QueryTask.class);
            if (rsp.results.documentLinks.isEmpty()) {
                parentOp.fail(Operation.STATUS_CODE_FORBIDDEN);
                return;
            }

            // The user is valid; query the auth provider to check if the credentials match
            String userLink = rsp.results.documentLinks.get(0);
            System.out.println("Found UserLink : " + userLink);
            this.userLink = userLink;
        };

        Operation queryOp = Operation
                .createPost(this, ServiceUriPaths.CORE_QUERY_TASKS)
                .setBody(q)
                .setCompletion(userServiceCompletion);
        setAuthorizationContext(queryOp, getSystemAuthorizationContext());
        sendRequest(queryOp);
    }

    public ClaimsVerificationState verify(String jwt , String userLink) throws VidmTokenException,
            GeneralSecurityException {

        System.out.println("Inside verify");
        if (userLink == null) {
            throw new GeneralSecurityException("UserLink Invalid : NULL");
        }
        SuiteToken suiteToken = getSuiteTokenObject(jwt);

        Claims.Builder builder = new Claims.Builder();
        builder.setIssuer(suiteToken.getIssuer());
        builder.setSubject(userLink);
        builder.setExpirationTime(suiteToken.getExpires() * 1000000);

        HashSet<String> audienceSet = new HashSet<String>();
        audienceSet.add(suiteToken.getAudience());
        builder.setAudience(audienceSet);

        System.out.println("\n\n\nSetting Audience : " + audienceSet);
        Claims claims = builder.getResult();

        ClaimsVerificationState claimsVerificationState = new ClaimsVerificationState();
        System.out.println("getting Audience : " + claims.getAudience());

        claimsVerificationState.audience = new HashSet<>(claims.getAudience());
        claimsVerificationState.expirationTime = claims.getExpirationTime();
        claimsVerificationState.issuedAt = claims.getIssuedAt();
        claimsVerificationState.issuer = claims.getIssuer();
        claimsVerificationState.jwtId = claims.getJwtId();
        claimsVerificationState.notBefore = claims.getNotBefore();
        claimsVerificationState.subject = claims.getSubject();
        System.out.println("Claim Verification state : " + claimsVerificationState +  "\n\n\n");

        return claimsVerificationState;
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
}

