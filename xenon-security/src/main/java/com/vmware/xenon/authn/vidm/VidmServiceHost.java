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

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Properties;
import java.util.logging.Level;

import com.vmware.xenon.common.AuthorizationSetupHelper;
import com.vmware.xenon.common.ServiceHost;
import com.vmware.xenon.common.Utils;
import com.vmware.xenon.services.common.ExampleService;
import com.vmware.xenon.services.common.RootNamespaceService;

public class VidmServiceHost extends ServiceHost {

    public static class VidmHostArguments extends Arguments {

        /**
         * Used to read the vIDM properties file as an input when xenon is started
         */
        public Path vidmProperties;

        /**
         * The email address of a user that should be granted "admin" privileges to all services
         */
        public String adminUser;

        /**
         * The password of the adminUser
         */
        public String adminUserPassword;

        /**
         * The email address of a user that should be granted privileges just to example services
         * that they own
         */
        public String exampleUser;

        /**
         * The password of the exampleUser
         */
        public String exampleUserPassword;
    }

    private VidmHostArguments args;

    public static void main(String[] args) throws Throwable {
        VidmServiceHost h = new VidmServiceHost();
        h.initialize(args);
        h.start();
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            h.log(Level.WARNING, "Host stopping ...");
            h.stop();
            h.log(Level.WARNING, "Host is stopped");
        }));
    }

    @Override
    public ServiceHost initialize(String[] args) throws Throwable {
        this.args = new VidmHostArguments();
        super.initialize(args, this.args);
        if (this.args.vidmProperties != null) {
            Properties prop = new Properties();
            prop.load(Files.newInputStream(this.args.vidmProperties));

            VidmProperties.setClientId(prop.getProperty("clientID"));
            VidmProperties.setClientSecret(prop.getProperty("clientSecret"));
            VidmProperties.setHostName(prop.getProperty("hostName"));
        }
        return this;
    }

    @Override
    public ServiceHost start() throws Throwable {
        super.start();

        startDefaultCoreServicesSynchronously();

        setAuthorizationContext(this.getSystemAuthorizationContext());

        //Add privileges for both authentication and verification service
        super.addPrivilegedService(VidmAuthenticationService.class);
        super.addPrivilegedService(VidmVerifierService.class);

        // Start the vIDM Authentication ans Verification Service
        super.startService(new VidmAuthenticationService());
        super.startService(new VidmVerifierService());

        // Start the root namespace factory: this will respond to the root URI (/) and list all
        // the factory services.
        super.startService(new RootNamespaceService());

        //Create a vIDM user in xenon which will be used as a document instance for
        //all users belonging to vIDM
        AuthorizationSetupHelper.create()
                .setHost(this)
                .setUserEmail(VidmProperties.VIDM_USER)
                .setUserPassword(VidmProperties.VIDM_USER_PASSWORD)
                .setIsAdmin(true)
                .start();

        if (this.args != null ) {

            if (this.args.adminUser != null) {
                AuthorizationSetupHelper.create()
                        .setHost(this)
                        .setUserEmail(this.args.adminUser)
                        .setUserPassword(this.args.adminUserPassword)
                        .setIsAdmin(true)
                        .start();
            }
            if (this.args.exampleUser != null) {
                AuthorizationSetupHelper.create()
                        .setHost(this)
                        .setUserEmail(this.args.exampleUser)
                        .setUserPassword(this.args.exampleUserPassword)
                        .setIsAdmin(false)
                        .setDocumentKind(Utils.buildKind(ExampleService.ExampleServiceState.class))
                        .start();
            }
        }

        setAuthorizationContext(null);

        return this;
    }

}