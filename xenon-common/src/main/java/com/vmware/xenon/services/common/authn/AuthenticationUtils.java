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

package com.vmware.xenon.services.common.authn;

import java.io.UnsupportedEncodingException;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.function.Consumer;

import com.vmware.xenon.common.Claims;
import com.vmware.xenon.common.Operation;
import com.vmware.xenon.common.OperationProcessingChain;
import com.vmware.xenon.common.RequestRouter;
import com.vmware.xenon.common.Service;
import com.vmware.xenon.common.ServiceHost;
import com.vmware.xenon.common.StatelessService;
import com.vmware.xenon.common.Utils;

public class AuthenticationUtils {
    public static final String BASIC_AUTH_NAME = "Basic";
    public static final String BASIC_AUTH_SEPARATOR = " ";
    public static final String BASIC_AUTH_USER_SEPARATOR = ":";

    public void startAuthProviderServices(ServiceHost host) {

    }

    public List<Class<? extends Service>> getPrivilegedServices() {
        return Collections.emptyList();
    }

    public static OperationProcessingChain getNewOperationProcessingChain(
            Consumer<Operation> authenticationHandler, Consumer<Operation> verificationHandler,
            StatelessService statelessService) {

        RequestRouter myRouter = new RequestRouter();
        myRouter.register(
                Service.Action.POST,
                new RequestRouter.RequestBodyMatcher<AuthenticationRequest>(
                        AuthenticationRequest.class, "kind",
                        AuthenticationRequest.Kind.AUTHENTICATION),
                authenticationHandler, "Authentication");
        myRouter.register(
                Service.Action.POST,
                new RequestRouter.RequestBodyMatcher<AuthenticationRequest>(
                        AuthenticationRequest.class, "kind",
                        AuthenticationRequest.Kind.VERIFICATION),
                verificationHandler, "Verification");
        OperationProcessingChain opProcessingChain = new OperationProcessingChain(statelessService);
        opProcessingChain.add(myRouter);
        return opProcessingChain;
    }

    public static String[] parseRequest(StatelessService service, Operation op, String headerName,
            String headerValue) {
        String authHeader = op.getRequestHeader(AuthenticationService.AUTHORIZATION_HEADER_NAME);

        // if no header specified, send a 401 response and a header asking for VIDM auth
        if (authHeader == null) {
            op.addResponseHeader(headerName, headerValue);
            op.fail(Operation.STATUS_CODE_UNAUTHORIZED);
            return null;
        }
        String[] authHeaderParts = authHeader.split(AuthenticationUtils.BASIC_AUTH_SEPARATOR);
        // malformed header; send a 400 response
        if (authHeaderParts.length != 2 || !authHeaderParts[0].equalsIgnoreCase(
                AuthenticationUtils.BASIC_AUTH_NAME)) {
            op.fail(Operation.STATUS_CODE_BAD_REQUEST);
            return null;
        }
        String authString;
        try {
            authString = new String(Base64.getDecoder().decode(authHeaderParts[1]), Utils.CHARSET);
        } catch (UnsupportedEncodingException e) {
            service.logWarning("Exception decoding auth header: %s", Utils.toString(e));
            op.setStatusCode(Operation.STATUS_CODE_BAD_REQUEST).complete();
            return null;
        }
        String[] userNameAndPassword = authString.split(
                AuthenticationUtils.BASIC_AUTH_USER_SEPARATOR);
        if (userNameAndPassword.length != 2) {
            op.fail(Operation.STATUS_CODE_BAD_REQUEST);
            return null;
        }
        return userNameAndPassword;
    }

    public static Operation.AuthorizationContext buildAuthorizationContext(String issuer ,
            String subject , Long expirationTime , Set<String> audience , String token) {
        Claims.Builder builder = new Claims.Builder();
        builder.setIssuer(issuer);
        builder.setSubject(subject);
        builder.setExpirationTime(expirationTime);
        builder.setAudience(audience);

        Claims claims = builder.getResult();

        Operation.AuthorizationContext.Builder ab = Operation.AuthorizationContext.Builder.create();
        ab.setClaims(claims);
        ab.setToken(token);
        ab.setPropagateToClient(true);

        return ab.getResult();
    }
}
