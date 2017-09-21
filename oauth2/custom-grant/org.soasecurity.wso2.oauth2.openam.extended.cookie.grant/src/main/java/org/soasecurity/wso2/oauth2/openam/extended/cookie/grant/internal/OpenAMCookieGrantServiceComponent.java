/*
 * Copyright (c) soasecurity.org All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.soasecurity.wso2.oauth2.openam.extended.cookie.grant.internal;


import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.ComponentContext;
import org.wso2.carbon.user.core.service.RealmService;

/**
 * @scr.component name="openam.cookie.grant" immediate="true"
 * @scr.reference name="user.realmservice.default"
 * interface="org.wso2.carbon.user.core.service.RealmService" cardinality="1..1"
 * policy="dynamic" bind="setRealmService" unbind="unsetRealmService"
 */
public class OpenAMCookieGrantServiceComponent {

    private static Log log = LogFactory.getLog(OpenAMCookieGrantServiceComponent.class);

    private static RealmService realmService;

    protected void activate(ComponentContext componentContext) {
        log.info("OpenAMCookieGrant bundle is activated.");

    }

    protected void setRealmService(RealmService realmService) {
        OpenAMCookieGrantServiceComponent.realmService = realmService;
        if (log.isDebugEnabled()) {
            log.debug("Realm Service is set in the OpenAM cookie grant bundle.");
        }
    }

    protected void unsetRealmService(RealmService realmService) {
        OpenAMCookieGrantServiceComponent.realmService = null;
        if (log.isDebugEnabled()) {
            log.debug("Realm Service is unset in the OpenAM cookie grant  bundle.");
        }
    }

    public static RealmService getRealmService() {
        return realmService;
    }
}
