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

public class VidmProperties {
    public static final String VIDM_AUTH_NAME = "Vidm";
    public static final String VIDM_AUTH_SEPARATOR = " ";
    public static final String VIDM_AUTH_USER_SEPARATOR = ":";
    private static String HOST_NAME ;
    private static String CLIENT_ID ;
    private static String CLIENT_SECRET ;

    public static void setHostName(String hostName) {
        VidmProperties.HOST_NAME = hostName ;
    }

    public static void setClientId(String clientId) {
        VidmProperties.CLIENT_ID = clientId ;
    }

    public static void setClientSecret(String clientSecret) {
        VidmProperties.CLIENT_SECRET = clientSecret ;
    }

    public static String getHostName() {
        return VidmProperties.HOST_NAME ;
    }

    public static String getClientId() {
        return VidmProperties.CLIENT_ID;
    }

    public static String getClientSecret() {
        return VidmProperties.CLIENT_SECRET;
    }
}
