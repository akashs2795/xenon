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
import com.vmware.xenon.services.common.ServiceUriPaths;

public class VidmConfigurationService extends StatefulService {
    public static final String FACTORY_LINK = ServiceUriPaths.CORE_AUTHN_CONFIG + "/vidm" ;

    public static Service createFactory() {
        Service service = FactoryService.create(VidmConfigurationService.class ,
                VidmConfigurationState.class);
        return service;
    }

    /**
     * The {@link VidmConfigurationState} represents a single user's identity.
     */
    public static class VidmConfigurationState extends ServiceDocument {
        public static final String FIELD_NAME_CLIENT_ID = "clientID";
        public static final String FIELD_NAME_CLIENT_SECRET = "clientSecret";
        public static final String FIELD_NAME_DOMAIN = "domain";
        public String clientId;
        public String clientSecret;
        public String domain;
    }

    public VidmConfigurationService() {
        super(VidmConfigurationState.class);
        super.toggleOption(ServiceOption.PERSISTENCE, false);
        super.toggleOption(ServiceOption.REPLICATION, true);
        super.toggleOption(ServiceOption.OWNER_SELECTION, true);
    }

    @Override
    public void handleDelete(Operation delete) {
        if (!delete.hasBody()) {
            delete.complete();
            return;
        }

        // A DELETE can be used to both stop the service, mark it deleted in the index
        // so its excluded from queries, but it can also set its expiration so its state
        // history is permanently removed
        VidmConfigurationState currentState = getState(delete);
        VidmConfigurationState st = delete.getBody(VidmConfigurationState.class);
        if (st.documentExpirationTimeMicros > 0) {
            currentState.documentExpirationTimeMicros = st.documentExpirationTimeMicros;
        }
        delete.complete();
    }

    @Override
    public void handleStart(Operation op) {
        if (!op.hasBody()) {
            op.fail(new IllegalArgumentException("body is required"));
            return;
        }

        VidmConfigurationState state = op.getBody(VidmConfigurationState.class);
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

        VidmConfigurationState newState = op.getBody(VidmConfigurationState.class);
        if (!validate(op, newState)) {
            return;
        }

        VidmConfigurationState currentState = getState(op);
        // if the email field has not changed and the userGroupsLinks field is either null
        // or the same in both the current state and the state passed in return a 304
        // response
        if (currentState.domain.equals(newState.domain)) {
            op.setStatusCode(Operation.STATUS_CODE_NOT_MODIFIED);
        } else {
            setState(op, newState);
        }
        op.complete();
    }

    private boolean validate(Operation op, VidmConfigurationState state) {
        if (state.domain == null) {
            op.fail(new IllegalArgumentException("domain name is required"));
            return false;
        }
        return true;
    }
}
