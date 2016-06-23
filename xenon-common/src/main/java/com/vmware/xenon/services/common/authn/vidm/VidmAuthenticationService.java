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

import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.util.Base64;
import java.util.HashMap;
import java.util.HashSet;

import com.vmware.horizon.common.api.token.SuiteToken;
import com.vmware.horizon.common.api.token.SuiteTokenConfiguration;
import com.vmware.horizon.common.api.token.SuiteTokenException;
import com.vmware.xenon.common.Claims;
import com.vmware.xenon.common.Operation;
import com.vmware.xenon.common.Operation.AuthorizationContext;
import com.vmware.xenon.common.ServiceDocument;
import com.vmware.xenon.common.StatelessService;
import com.vmware.xenon.common.Utils;
import com.vmware.xenon.services.common.QueryTask;
import com.vmware.xenon.services.common.ServiceUriPaths;
import com.vmware.xenon.services.common.UserService;
import com.vmware.xenon.services.common.authn.AuthenticationRequest;
import com.vmware.xenon.services.common.authn.AuthenticationRequest.AuthenticationRequestType;

public class VidmAuthenticationService extends StatelessService {

    public static String SELF_LINK = ServiceUriPaths.CORE_AUTHN_VIDM;

    public static final String WWW_AUTHENTICATE_HEADER_NAME = "WWW-Authenticate";
    public static final String WWW_AUTHENTICATE_HEADER_VALUE = "Basic realm=\"xenon\"";
    public static final String AUTHORIZATION_HEADER_NAME = "Authorization";
    public static final String VIDM_AUTH_NAME = "Vidm";
    private static final String VIDM_AUTH_SEPERATOR = " ";
    private static final String VIDM_AUTH_USER_SEPERATOR = ":";
    public static final String VIDM_USER = "vidm@localhost" ;

    protected String hostName ;
    protected String clientID ;
    protected String clientSecret ;
    protected String authToken ;

    @Override
    public void authorizeRequest(Operation op) {
        op.complete();
    }

    @Override
    public void handlePost(Operation op) {

        System.out.print(true);
        AuthenticationRequestType requestType = op.getBody(AuthenticationRequest.class).requestType;
        // default to login for backward compatibility
        if (requestType == null) {
            requestType = AuthenticationRequestType.LOGIN;
        }
        switch (requestType) {
        case LOGIN:
            handleLogin(op);
            break;
        case LOGOUT:
            handleLogout(op);
            break;
        default:
            break;
        }
    }

    private void handleLogout(Operation op) {
        if (op.getAuthorizationContext() == null) {
            op.complete();
            return;
        }
        String userLink = op.getAuthorizationContext().getClaims().getSubject();
        if (!associateAuthorizationContext(op, userLink, 0 , this.authToken)) {
            op.setStatusCode(Operation.STATUS_CODE_SERVER_FAILURE_THRESHOLD).complete();
            return;
        }
        op.complete();
    }

    private void handleLogin(Operation op) {
        String authHeader = op.getRequestHeader(AUTHORIZATION_HEADER_NAME);

        // if no header specified, send a 401 response and a header asking for VIDM auth
        if (authHeader == null) {
            op.addResponseHeader(WWW_AUTHENTICATE_HEADER_NAME, WWW_AUTHENTICATE_HEADER_VALUE);
            op.fail(Operation.STATUS_CODE_UNAUTHORIZED);
            return;
        }
        String[] authHeaderParts = authHeader.split(VIDM_AUTH_SEPERATOR);
        // malformed header; send a 400 response
        if (authHeaderParts.length != 2 || !authHeaderParts[0].equalsIgnoreCase(VIDM_AUTH_NAME)) {
            op.fail(Operation.STATUS_CODE_BAD_REQUEST);
            return;
        }
        String authString;
        try {
            authString = new String(Base64.getDecoder().decode(authHeaderParts[1]), Utils.CHARSET);
        } catch (UnsupportedEncodingException e) {
            logWarning("Exception decoding auth header: %s", Utils.toString(e));
            op.setStatusCode(Operation.STATUS_CODE_BAD_REQUEST).complete();
            return;
        }
        String[] userNameAndPassword = authString.split(VIDM_AUTH_USER_SEPERATOR);
        if (userNameAndPassword.length != 2) {
            op.fail(Operation.STATUS_CODE_BAD_REQUEST);
            return;
        }

        // validate that the user is valid
        queryUserService(op, userNameAndPassword[0], userNameAndPassword[1]);
    }

    private void queryUserService(Operation parentOp, String userName, String password) {
        QueryTask q = new QueryTask();
        q.querySpec = new QueryTask.QuerySpecification();

        String kind = Utils.buildKind(UserService.UserState.class);
        QueryTask.Query kindClause = new QueryTask.Query()
                .setTermPropertyName(ServiceDocument.FIELD_NAME_KIND)
                .setTermMatchValue(kind);
        q.querySpec.query.addBooleanClause(kindClause);

        QueryTask.Query emailClause = new QueryTask.Query()
                .setTermPropertyName(UserService.UserState.FIELD_NAME_EMAIL)
                .setTermMatchValue(VIDM_USER);
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
            requestAccessToken(parentOp, userLink, userName, password);
        };

        Operation queryOp = Operation
                .createPost(this, ServiceUriPaths.CORE_QUERY_TASKS)
                .setBody(q)
                .setCompletion(userServiceCompletion);
        setAuthorizationContext(queryOp, getSystemAuthorizationContext());
        sendRequest(queryOp);
    }

    public void requestAccessToken(Operation op , String userLink , String userName, String password) {

        this.clientID = "java_test_client";
        this.clientSecret = "vmware123456789";
        this.hostName = "https://blr-2nd-1-dhcp666.eng.vmware.com";
        String targetURL =
                "/SAAS/API/1.0/oauth2/token?grant_type=password&username=" + userName
                        + "&password=" + password;

        Base64.Encoder e = Base64.getEncoder();
        String authCode = this.clientID + ":" + this.clientSecret;
        byte[] authCodeBytes = new byte[0];
        try {
            authCodeBytes = authCode.getBytes("UTF-8");
        } catch (UnsupportedEncodingException encodingException) {
            encodingException.printStackTrace();
        }
        String authString = e.encodeToString(authCodeBytes);
        createPost(op , userLink , this.hostName + targetURL , authString);
    }

    public void createPost(Operation parentOp , String userLink , String targetUrl , String authString) {
        Operation postRequest = Operation.createPost(URI.create(targetUrl))
                .setReferer(this.getUri())
                .setBody(new Object())
                .addRequestHeader(AUTHORIZATION_HEADER_NAME , "Basic " + authString)
                .setCompletion((authOp ,authEx) -> {
                    if (authEx != null) {
                        logWarning("Exception validating user credentials: %s",
                                Utils.toString(authEx));
                        parentOp.setBodyNoCloning(authOp.getBodyRaw()).fail(
                                Operation.STATUS_CODE_SERVER_FAILURE_THRESHOLD);
                        return;
                    }

                    String response = authOp.getBody(String.class);
                    ConverterUtil converter = new ConverterUtil();
                    HashMap<String, String> responseMap = new HashMap<String, String>(
                            converter.convertToMap(response));

                    String accessToken = responseMap.get("access_token");
                    this.authToken = accessToken ;
                    long expiryTime = Integer.parseInt(responseMap.get("expires_in"));

                    if (!associateAuthorizationContext(parentOp, userLink,
                            (Utils.getNowMicrosUtc() + (expiryTime * 1000000)) , accessToken)) {
                        parentOp.fail(Operation.STATUS_CODE_SERVER_FAILURE_THRESHOLD);
                        return;
                    }

                    parentOp.complete();
                });
        this.getHost().sendRequest(postRequest);
    }

    private SuiteToken getSuiteTokenObject(String token) {
        SuiteTokenConfiguration s = new SuiteTokenConfiguration();
        s.setPublicKeyUrl(this.hostName + "/SAAS/API/1.0/REST/auth/token?attribute=publicKey");
        s.setRevokeCheckUrl(this.hostName + "/SAAS/API/1.0/REST/auth/token?attribute=isRevoked");

        SuiteToken suiteToken = null ;
        try {
            suiteToken = SuiteToken.decodeSuiteToken(token);
        } catch (SuiteTokenException e) {
            return null;
        }
        return suiteToken ;
    }

    private boolean associateAuthorizationContext(Operation op, String userLink, long expirationTime  ,String token) {

        this.getHost().setVidmUserLink(userLink);
        SuiteToken suiteToken = getSuiteTokenObject(token);
        if (suiteToken ==  null) {
            return false;
        }

        Claims.Builder builder = new Claims.Builder();
        builder.setIssuer(suiteToken.getIssuer());
        builder.setSubject(userLink);
        builder.setExpirationTime(suiteToken.getExpires() * 1000000);

        HashSet<String> audienceSet = new HashSet<String>();
        audienceSet.add(suiteToken.getAudience());
        builder.setAudience(audienceSet);

        // Generate token for set of claims
        Claims claims = builder.getResult();

        AuthorizationContext.Builder ab = AuthorizationContext.Builder.create();
        ab.setClaims(claims);
        ab.setToken(token);
        ab.setPropagateToClient(true);

        // Associate resulting authorization context with operation.
        setAuthorizationContext(op, ab.getResult());
        return true;
    }
}
