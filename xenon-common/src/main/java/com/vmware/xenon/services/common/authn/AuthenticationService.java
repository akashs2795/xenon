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

import com.vmware.xenon.common.Claims;
import com.vmware.xenon.common.Operation;
import com.vmware.xenon.common.OperationProcessingChain;

public interface AuthenticationService {
    public static final String AUTHORIZATION_HEADER_NAME = "Authorization";

    public OperationProcessingChain getOperationProcessingChain();

    public void handlePostForAuthentication(Operation op) ;

    /**
     * handleLogout by making the expiration time of the token as 0
     * @param op
     */
    public void handleLogout(Operation op) ;

    /**
     * handleLogin method should extract userName and password from the request.
     *
     * on completion , call queryUserService(op , userName , password) .
     * @param op
     */
    public void handleLogin(Operation op) ;

    /**
     * queryUserService doesn't use username and password directly. It simply queries for the
     * dummy user for the auth provider created when the host was started. If the query fails,
     * the operation is not continued forward however on success, the self link of the document is
     * saved as the userLink which will be used as a subject in Claims itself being used for
     * creating an authorization context
     *
     * on completion , Call authenticate(op, String userLink, String userName ,
                                String password);
     *
     * @param op
     * @param userName
     * @param password
     */
    public void queryUserService(Operation op, String userName, String password);

    /**
     * Authenticate function is responsible for communicating with the auth provider and
     * authenticating the user credentials. An access/auth token is expected from the auth
     * provider when authentication is successful.
     *
     * on completion , call associateAuthorizationContext(Operation op, String userLink,
                    long expirationTime, String token);
     * @param op
     * @param userLink
     * @param userName
     * @param password
     */
    public void authenticate(Operation op, String userLink, String userName,
            String password);

    /**
     * Extract Claims data from the token, construct Claims object which then is used for
     * creating an authorization context. Make the subject for Claims as userLink.
     * If expiration time was 0, it means that the call came from handleLogout function. Make the
     * expiry of token as current time or 0 indicating that token is now expired.
     * @param op
     * @param userLink
     * @param expirationTime
     * @param token
     * @return
     */
    public boolean associateAuthorizationContext(Operation op, String userLink,
            long expirationTime, String token);

    /**
     * handlePostForVerification function is triggered when a POST request is made to the verification
     * service of any auth provider. It sets the operation state as the Claims
     * after successful verification
     */
    public void handlePostForVerification(Operation op) ;

    /**
     * The auth provider has to implement this method which will decode the token
     * and generate a Claims object in return. If unable to decode the token or
     * create the object, throw an appropriate exception
     * @return Claims
     * @throws Exception
     */
    public Claims verify(String token) throws Exception ;
}
