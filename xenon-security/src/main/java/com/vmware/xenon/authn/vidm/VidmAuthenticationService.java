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

import java.io.StringReader;
import java.io.UnsupportedEncodingException;
import java.lang.reflect.Type;
import java.net.URI;
import java.util.Base64;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.logging.Level;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.google.gson.reflect.TypeToken;

import com.google.gson.stream.JsonReader;
import com.vmware.horizon.common.api.token.SuiteToken;
import com.vmware.xenon.authn.common.AuthenticationService;
import com.vmware.xenon.authn.vidm.VidmUtils.VidmTokenException;
import com.vmware.xenon.common.Claims;
import com.vmware.xenon.common.Operation;
import com.vmware.xenon.common.Operation.AuthorizationContext;
import com.vmware.xenon.common.ServiceDocument;
import com.vmware.xenon.common.UriUtils;
import com.vmware.xenon.common.Utils;
import com.vmware.xenon.services.common.QueryTask;
import com.vmware.xenon.services.common.ServiceUriPaths;
import com.vmware.xenon.services.common.UserService;
import jdk.nashorn.internal.parser.JSONParser;

import javax.sound.midi.SysexMessage;

public class VidmAuthenticationService extends AuthenticationService {

    public static String SELF_LINK = ServiceUriPaths.CORE_AUTHN + "/vidm";

    protected String hostName = VidmProperties.getHostName();
    protected String clientID = VidmProperties.getClientId();
    protected String clientSecret = VidmProperties.getClientSecret();

    @Override
    public void handleLogout(Operation op) {
        if (op.getAuthorizationContext() == null) {
            op.complete();
            return;
        }
        String userLink = op.getAuthorizationContext().getClaims().getSubject();
        String accessToken = op.getRequestHeader(Operation.REQUEST_AUTH_TOKEN_HEADER);
        if (!associateAuthorizationContext(op, userLink, 0 , accessToken)) {
            op.setStatusCode(Operation.STATUS_CODE_SERVER_FAILURE_THRESHOLD).complete();
            return;
        }
        op.complete();
    }

    @Override
    public void handleLogin(Operation op) {
        String authHeader = op.getRequestHeader(AUTHORIZATION_HEADER_NAME);

        // if no header specified, send a 401 response and a header asking for VIDM auth
        if (authHeader == null) {
            op.addResponseHeader(WWW_AUTHENTICATE_HEADER_NAME, WWW_AUTHENTICATE_HEADER_VALUE);
            op.fail(Operation.STATUS_CODE_UNAUTHORIZED);
            return;
        }
        String[] authHeaderParts = authHeader.split(VidmProperties.VIDM_AUTH_SEPARATOR);
        // malformed header; send a 400 response
        if (authHeaderParts.length != 2 || !authHeaderParts[0].equalsIgnoreCase(VidmProperties.VIDM_AUTH_NAME)) {
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
        String[] userNameAndPassword = authString.split(VidmProperties.VIDM_AUTH_USER_SEPARATOR);
        if (userNameAndPassword.length != 2) {
            op.fail(Operation.STATUS_CODE_BAD_REQUEST);
            return;
        }

        // validate that the user is valid
        authenticate(op, userNameAndPassword[0], userNameAndPassword[1]);
    }

    public void authenticate(Operation op , String userName, String password) {
        if (this.hostName == null || this.clientID == null || this.clientSecret == null) {
            logWarning("Valid vIDM configuration not found ");
            op.setStatusCode(Operation.STATUS_CODE_NOT_FOUND).complete();
            return;
        }
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

        Operation postRequest = Operation.createPost(URI.create(this.hostName + targetURL))
                .setReferer(this.getUri())
                .setBody(new Object())
                .addRequestHeader(AUTHORIZATION_HEADER_NAME , "Basic " + authString)
                .setCompletion((authOp ,authEx) -> {
                    if (authEx != null) {
                        logWarning("Exception validating user credentials");
                        op.setBodyNoCloning(authOp.getBodyRaw()).fail(
                                Operation.STATUS_CODE_SERVER_FAILURE_THRESHOLD);
                        return;
                    }

                    String response = authOp.getBody(String.class);

                    Gson gson = new Gson();
                    Type type = new TypeToken<Map<String, String>>(){}.getType();
                    HashMap<String, String> responseMap = new HashMap<String, String>(
                            gson.fromJson(response, type));

                    String accessToken = responseMap.get("access_token");
                    long expiryTime = Integer.parseInt(responseMap.get("expires_in"));

                    if (accessToken == null) {
                        logWarning("Exception validating user credentials");
                        op.fail(Operation.STATUS_CODE_FORBIDDEN);
                        return;
                    }

                    createUserPresence(op , userName , accessToken , expiryTime);
                });
        this.getHost().sendRequest(postRequest);
    }

    public void createUserPresence(Operation parentOp, String userName, String token,
            long expiryTime) {
        QueryTask q = new QueryTask();
        q.querySpec = new QueryTask.QuerySpecification();

        String kind = Utils.buildKind(VidmUserService.VidmUserState.class);
        QueryTask.Query kindClause = new QueryTask.Query()
                .setTermPropertyName(ServiceDocument.FIELD_NAME_KIND)
                .setTermMatchValue(kind);
        q.querySpec.query.addBooleanClause(kindClause);

        QueryTask.Query userNameClause = new QueryTask.Query()
                .setTermPropertyName(VidmUserService.VidmUserState.FIELD_NAME_USERNAME)
                .setTermMatchValue(userName);
        userNameClause.occurance = QueryTask.Query.Occurance.MUST_OCCUR;

        q.querySpec.query.addBooleanClause(userNameClause);
        q.taskInfo.isDirect = true;

        Operation.CompletionHandler userServiceCompletion = (o, ex) -> {
            if (ex != null) {
                logWarning("Exception validating user: %s", Utils.toString(ex));
                parentOp.setBodyNoCloning(o.getBodyRaw()).fail(o.getStatusCode());
                return;
            }

            QueryTask rsp = o.getBody(QueryTask.class);
            if (rsp.results.documentLinks.isEmpty()) {
                logInfo("Creating a presence for User");

                String targetURL = "/SAAS/jersey/manager/api/scim/Me";

                Operation getUserInfoRequest = Operation.createGet(URI.create(this.hostName +
                        targetURL))
                        .setReferer(this.getUri())
                        .setBody(new Object())
                        .addRequestHeader(AUTHORIZATION_HEADER_NAME , "HZN " + token)
                        .setCompletion((authOp ,authEx) -> {
                            if (authEx != null) {
                                System.out.println("Found the error");
                                logWarning("Exception validating user credentials");
                                parentOp.setBodyNoCloning(authOp.getBodyRaw()).fail(
                                        Operation.STATUS_CODE_SERVER_FAILURE_THRESHOLD);
                                return;
                            }

                            String response = authOp.getBody(String.class);
                            System.out.println("response : " + response);

                            JsonReader reader = new JsonReader(new StringReader(response));
                            JsonObject json = reader.
                            json.
                            String email = responseMap.get("emails");
                            VidmUserService.VidmUserState state = new VidmUserService.
                                    VidmUserState();
                            state.userName = userName;
                            state.email = email;
                            Operation createUserRequest = Operation.createPost(
                                    UriUtils.buildUri(this.getHost(), VidmUserService.FACTORY_LINK))
                                    .setReferer(this.getUri())
                                    .setBody(state)
                                    .setCompletion((opp ,exx) -> {
                                        if (opp != null) {
                                            logWarning("Exception validating user credentials");
                                            parentOp.setBodyNoCloning(authOp.getBodyRaw()).fail(
                                                    Operation.STATUS_CODE_SERVER_FAILURE_THRESHOLD);
                                            return;
                                        }

                                        String userDetailsResponse = opp.getBody(String.class);

                                        Gson userDetailsGson = new Gson();
                                        Type userDetailsType = new TypeToken<Map<String,
                                                String>>() {}.getType();
                                        HashMap<String, String> userDetailsResponseMap =
                                                new HashMap<String, String>(
                                                        userDetailsGson.fromJson(response,
                                                                userDetailsType));

                                        String userLink = userDetailsResponseMap
                                                .get("documentSelfLink");
                                        if (!associateAuthorizationContext(parentOp, userLink,
                                                (Utils.getNowMicrosUtc() + (expiryTime * 1000000))
                                                , token)) {
                                            parentOp.fail(
                                                    Operation.STATUS_CODE_SERVER_FAILURE_THRESHOLD);
                                            return;
                                        }

                                        parentOp.complete();
                                    });
                            this.getHost().sendRequest(createUserRequest);

                        });
                this.getHost().sendRequest(getUserInfoRequest);
            }
            else {
                //The user document already exists. Use this as the selfLink
                logInfo("User Document already present in xenon");
                String userLink = rsp.results.documentLinks.get(0);
                if (!associateAuthorizationContext(parentOp, userLink,
                        (Utils.getNowMicrosUtc() + (expiryTime * 1000000)), token)) {
                    parentOp.fail(Operation.STATUS_CODE_SERVER_FAILURE_THRESHOLD);
                    return;
                }

                parentOp.complete();
            }
        };

        Operation queryOp = Operation
                .createPost(this, ServiceUriPaths.CORE_QUERY_TASKS)
                .setBody(q)
                .setCompletion(userServiceCompletion);
        setAuthorizationContext(queryOp, getSystemAuthorizationContext());
        sendRequest(queryOp);
    }

    public boolean associateAuthorizationContext(Operation op, String userLink, long expirationTime  ,String token) {

        SuiteToken suiteToken ;
        try {
            suiteToken = VidmUtils.getSuiteTokenObject(token);
        } catch (VidmTokenException e) {
            log(Level.WARNING , "Error extracting the token data %s" , e.getMessage());
            return false;
        }

        /**
         * If expirationTime is 0 , ie request coming from handleLogout. Set expiry time of the
         * token to the current time indicating the token just got expired.
         */
        if (expirationTime == 0) {
            suiteToken.setExpires(Utils.getNowMicrosUtc());
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
