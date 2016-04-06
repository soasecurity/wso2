/*
 *  Copyright (c) 2106 soasecurity.org. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.soasecurity.wso2.custom.provisioning.connector.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.ComponentContext;
import org.soasecurity.wso2.custom.provisioning.connector.CustomProvisioningConnectorFactory;
import org.wso2.carbon.identity.provisioning.AbstractProvisioningConnectorFactory;


/**
 * @scr.component name=
 * "org.soasecurity.wso2.custom.provisioning.connector.internal.CustomConnectorServiceComponent"
 * immediate="true"
 */
public class CustomConnectorServiceComponent {

    private static Log log = LogFactory.getLog(CustomConnectorServiceComponent.class);

    protected void activate(ComponentContext context) {

        if (log.isDebugEnabled()) {
            log.debug("Activating SOASecurityConnectorServiceComponent");
        }

        try {
            CustomProvisioningConnectorFactory provisioningConnectorFactory = new CustomProvisioningConnectorFactory();

            context.getBundleContext().registerService(
                    AbstractProvisioningConnectorFactory.class.getName(),
                    provisioningConnectorFactory, null);
            if (log.isDebugEnabled()) {
                log.debug("SOASecurity Identity Provisioning Connector bundle is activated");
            }
        } catch (Throwable e) {
            log.error(" Error while activating SOASecurity Identity Provisioning Connector ", e);
        }
    }
}
