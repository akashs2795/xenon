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

import com.vmware.xenon.common.FactoryService;
import com.vmware.xenon.common.Operation;
import com.vmware.xenon.common.Service;
import com.vmware.xenon.common.ServiceDocument;
import com.vmware.xenon.common.StatefulService;
import com.vmware.xenon.services.common.AuthorizationCacheUtils;
import com.vmware.xenon.services.common.ServiceUriPaths;

public class VidmUserService extends StatefulService {
    public static final String FACTORY_LINK = ServiceUriPaths.CORE_AUTHZ_USERS + "/vidm";

    public static Service createFactory() {
        return FactoryService.createIdempotent(VidmUserService.class);
    }

    /**
     * The {@link VidmUserState} represents a single user's identity.
     */
    public static class VidmUserState extends ServiceDocument {
        public static final String FIELD_NAME_EMAIL = "email";
        public static final String FIELD_NAME_USERNAME = "username";
        public String email;
        public String userName;
    }

    public VidmUserService() {
        super(VidmUserState.class);
        super.toggleOption(ServiceOption.PERSISTENCE, false);
        super.toggleOption(ServiceOption.REPLICATION, true);
        super.toggleOption(ServiceOption.OWNER_SELECTION, true);
    }

    @Override
    public void handleRequest(Operation request, OperationProcessingStage opProcessingStage) {
        if (request.getAction() == Action.DELETE || request.getAction() == Action.PUT ||
                request.getAction() == Action.PATCH) {
            VidmUserState VidmUserState = null;
            if (request.isFromReplication() && request.hasBody()) {
                VidmUserState = getBody(request);
            } else {
                VidmUserState = getState(request);
            }
            if (VidmUserState != null) {
                AuthorizationCacheUtils.clearAuthzCacheForUser(this, request, VidmUserState.documentSelfLink);
            }
        }
        super.handleRequest(request, opProcessingStage);
    }

    @Override
    public void handleStart(Operation op) {
        if (!op.hasBody()) {
            op.fail(new IllegalArgumentException("body is required"));
            return;
        }

        VidmUserState state = op.getBody(VidmUserState.class);
        if (!validate(op, state)) {
            return;
        }
        op.complete();
    }

    @Override
    public void handlePut(Operation op) {
        if (!op.hasBody()) {
            op.fail(new IllegalArgumentException("body is required"));
            return;
        }

        VidmUserState newState = op.getBody(VidmUserState.class);
        if (!validate(op, newState)) {
            return;
        }

        VidmUserState currentState = getState(op);
        // if the email field has not changed return a 304 response
        if (currentState.userName.equals(newState.userName)) {
            op.setStatusCode(Operation.STATUS_CODE_NOT_MODIFIED);
        } else {
            setState(op, newState);
        }
        op.complete();
    }

    @Override
    public void handlePatch(Operation op) {
        if (!op.hasBody()) {
            op.fail(new IllegalArgumentException("body is required"));
            return;
        }
        VidmUserState currentState = getState(op);
        VidmUserState newState = op.getBody(VidmUserState.class);
        if (newState.userName != null) {
            currentState.userName = newState.userName;
        }
        op.setBody(currentState);
        op.complete();
    }

    private boolean validate(Operation op, VidmUserState state) {
        if (state.userName == null) {
            op.fail(new IllegalArgumentException("userName is required"));
            return false;
        }
        return true;
    }
}
