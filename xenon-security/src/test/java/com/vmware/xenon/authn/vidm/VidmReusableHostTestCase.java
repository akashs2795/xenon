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

import java.util.concurrent.TimeUnit;

import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.rules.RuleChain;
import org.junit.rules.TestRule;
import org.junit.rules.TestWatcher;
import org.junit.runner.Description;

import com.vmware.xenon.common.AuthorizationSetupHelper;
import com.vmware.xenon.common.CommandLineArgumentParser;
import com.vmware.xenon.common.UriUtils;
import com.vmware.xenon.common.test.TestContext;
import com.vmware.xenon.services.common.ServiceUriPaths;

public class VidmReusableHostTestCase {

    private static final int MAINTENANCE_INTERVAL_MILLIS = 250;

    private static VidmVerificationHost HOST;

    protected VidmVerificationHost host;

    public boolean enableAuth = false;

    public String adminEmail = "admin@vmware.com";

    public String adminPassword = "changeme";

    @BeforeClass
    public static void setUpOnce() throws Exception {
        startHost(false);
    }

    private static void startHost(boolean enableAuth) throws Exception {
        HOST = VidmVerificationHost.create(0);
        HOST.setMaintenanceIntervalMicros(TimeUnit.MILLISECONDS
                .toMicros(MAINTENANCE_INTERVAL_MILLIS));
        CommandLineArgumentParser.parseFromProperties(HOST);
        HOST.setStressTest(HOST.isStressTest);
        HOST.setAuthorizationEnabled(enableAuth);
        try {
            HOST.start();
        } catch (Throwable e) {
            throw new Exception(e);
        }
    }

    @Before
    public void setUpPerMethod() throws Throwable {
        CommandLineArgumentParser.parseFromProperties(this);
        this.host = HOST;

        if (this.enableAuth) {

            if (!this.host.isAuthorizationEnabled()) {
                this.host.log("Restarting host to enable authorization");
                tearDownOnce();
                startHost(true);
                this.host = HOST;
            }

            this.host.log("Auth is enabled. Creating users");
            setUpAuthUsers();
            switchToAuthUser();
        }
    }

    protected void setUpAuthUsers()throws Throwable  {

        TestContext testContext = this.host.testCreate(1);

        AuthorizationSetupHelper.AuthSetupCompletion authCompletion = (ex) -> {
            if (ex != null) {
                testContext.failIteration(ex);
                return;
            }
            testContext.completeIteration();
        };

        // create admin user. if it already exists, skip creation.
        this.host.setSystemAuthorizationContext();
        AuthorizationSetupHelper.create()
                .setHost(this.host)
                .setUserEmail(this.adminEmail)
                .setUserPassword(this.adminPassword)
                .setUserSelfLink(this.adminEmail)
                .setIsAdmin(true)
                .setCompletion(authCompletion)
                .start();
        testContext.await();
        this.host.resetAuthorizationContext();

    }

    protected void switchToAuthUser() throws Throwable {
        String userServicePath = UriUtils
                .buildUriPath(ServiceUriPaths.CORE_AUTHZ_USERS, this.adminEmail);
        this.host.assumeIdentity(userServicePath);
    }


    protected TestRule watcher = new TestWatcher() {
        protected void starting(Description description) {
            HOST.log("Running test: " + description.getMethodName());
        }
    };

    @Rule
    public TestRule chain = RuleChain.outerRule(this.watcher);

    @AfterClass
    public static void tearDownOnce() {
        HOST.tearDownInProcessPeers();
        HOST.tearDown();
    }

    @After
    public void tearDownPerMethod() {
        if (this.enableAuth) {
            clearAuthorization();
        }
    }

    protected void clearAuthorization() {
        this.host.resetAuthorizationContext();
    }

}
