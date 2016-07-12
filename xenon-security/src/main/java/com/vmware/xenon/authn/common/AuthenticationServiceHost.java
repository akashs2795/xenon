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

package com.vmware.xenon.authn.common;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Properties;
import java.util.logging.Level;

import com.vmware.xenon.authn.vidm.VidmProperties;
import com.vmware.xenon.common.AuthorizationSetupHelper;
import com.vmware.xenon.common.ServiceHost;
import com.vmware.xenon.common.Utils;
import com.vmware.xenon.services.common.ExampleService;
import com.vmware.xenon.services.common.RootNamespaceService;

public class AuthenticationServiceHost extends ServiceHost {

    private HashMap<String , Path> authProviders;
    private String[] providers ;
    private int providerCount ;

    public static final String AUTHENTICATION_CLASS_NAME = "AuthenticationService" ;
    public static final String VERIFICATION_CLASS_NAME = "VerifierService" ;
    public static final String PACKAGE_NAME = "com.vmware.xenon.authn";

    public static class AuthenticationHostArguments extends Arguments {
        /**
         * Comma separated list of one or more providers
         * e.g --providers=vidm,google,facebook
         */
        public String[] providers;

        /**
         * Comma separated list of one or more properties file corresponding to providers
         * NOTE : Order of providers and properties file must remain same
         * e.g --providers=vidm,google --providerProperties=**path-to-vidm-prop**,
         * **path-to-google-prop**
         */
        public String[] providerProperties;


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

    private AuthenticationHostArguments args;

    public static void main(String[] args) throws Throwable {
        AuthenticationServiceHost h = new AuthenticationServiceHost();
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
        this.args = new AuthenticationHostArguments();
        super.initialize(args, this.args);
        this.providers = this.args.providers;

        this.authProviders = new HashMap<String, Path>();

        int count;
        if (this.args.providers != null) {
            this.providerCount = this.args.providers.length;
            for (count = 0 ; count < this.providerCount ; count++ ) {
                this.authProviders.put(this.args.providers[count].toLowerCase(),
                        Paths.get(this.args.providerProperties[count]));
            }
        }

        if (this.authProviders.containsKey("vidm")) {
            Properties prop = new Properties();
            prop.load(Files.newInputStream(this.authProviders.get("vidm")));

            VidmProperties.setClientId(prop.getProperty("clientID"));
            VidmProperties.setClientSecret(prop.getProperty("clientSecret"));
            VidmProperties.setHostName(prop.getProperty("hostName"));
        }
        return this;
    }

    @Override
    @SuppressWarnings("unchecked")
    public ServiceHost start() throws Throwable {
        super.start();

        startDefaultCoreServicesSynchronously();

        setAuthorizationContext(this.getSystemAuthorizationContext());

        int count;
        for (count = 0 ; count < this.providerCount ; count++ ) {

            String authenticationClassName = AuthenticationServiceHost.PACKAGE_NAME +
                    "." + this.providers[count].toLowerCase() + "." + this.providers[count] +
                    AuthenticationServiceHost.AUTHENTICATION_CLASS_NAME ;
            String verificationClassName = AuthenticationServiceHost.PACKAGE_NAME +
                    "." + this.providers[count].toLowerCase() + "." + this.providers[count] +
                    AuthenticationServiceHost.VERIFICATION_CLASS_NAME ;

            Class<? extends AuthenticationService> authenticationClass =
                    (Class<? extends AuthenticationService>)Class.forName(authenticationClassName);
            Class<? extends VerifierService> verificationClass =
                    (Class<? extends VerifierService>)Class.forName(verificationClassName);

            //Add privileges for both authentication and verification service
            super.addPrivilegedService(authenticationClass);
            super.addPrivilegedService(verificationClass);

            // Start the Authentication ans Verification Service
            super.startService(authenticationClass.newInstance());
            super.startService(verificationClass.newInstance());

        }

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