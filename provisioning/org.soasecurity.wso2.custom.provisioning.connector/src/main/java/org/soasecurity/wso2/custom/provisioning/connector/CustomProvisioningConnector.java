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

package org.soasecurity.wso2.custom.provisioning.connector;


import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.provisioning.*;

import java.util.List;
import java.util.Map;
import java.util.Properties;

public class CustomProvisioningConnector extends AbstractOutboundProvisioningConnector {

    private static final long serialVersionUID = 8465869197181038555L;

    private static final Log log = LogFactory.getLog(CustomProvisioningConnector.class);
    private Properties configs;

    @Override
    /**
     *
     */
    public void init(Property[] provisioningProperties) throws IdentityProvisioningException {
        Properties configs = new Properties();

        if (provisioningProperties != null && provisioningProperties.length > 0) {
            for (Property property : provisioningProperties) {
                configs.put(property.getName(), property.getValue());
                if (IdentityProvisioningConstants.JIT_PROVISIONING_ENABLED.equals(property
                        .getName()) && "1".equals(property.getValue())) {
                    jitProvisioningEnabled = true;
                }
            }
        }

        this.configs = configs;
    }

    @Override
    /**
     *
     */
    public ProvisionedIdentifier provision(ProvisioningEntity provisioningEntity) throws IdentityProvisioningException {

        String provisionedId = null;

        if (provisioningEntity != null) {

            if (provisioningEntity.isJitProvisioning() && !isJitProvisioningEnabled()) {
                log.debug("JIT provisioning disabled for SOASecurity connector");
                return null;
            }

            if (provisioningEntity.getEntityType() == ProvisioningEntityType.USER) {
                if (provisioningEntity.getOperation() == ProvisioningOperation.DELETE) {
                    deleteUser(provisioningEntity);
                } else if (provisioningEntity.getOperation() == ProvisioningOperation.POST) {
                    provisionedId = createUser(provisioningEntity);
                } else if (provisioningEntity.getOperation() == ProvisioningOperation.PUT) {
                    updateUser(provisioningEntity);
                } else {
                    log.warn("Unsupported provisioning operation.");
                }
            } else {
                log.warn("Unsupported provisioning entity.");
            }
        }

        // creates a provisioned identifier for the provisioned user.
        ProvisionedIdentifier identifier = new ProvisionedIdentifier();
        identifier.setIdentifier(provisionedId);
        return identifier;
    }



    private void deleteUser(ProvisioningEntity provisioningEntity) {


    }

    private void updateUser(ProvisioningEntity provisioningEntity) {


    }

    private String createUser(ProvisioningEntity provisioningEntity) {

        log.info("===================================== Logging Configuration ==================================");

        log.info("URL Property :  " + configs.getProperty(CustomProvisioningConnectorConstants.PROPERTY_NAME_URL));
        log.info("Username Property :  " + configs.getProperty(CustomProvisioningConnectorConstants.PROPERTY_NAME_USERNAME));
        log.info("Password Property :  " + configs.getProperty(CustomProvisioningConnectorConstants.PROPERTY_NAME_PASSWORD));

        log.info("==============================================================================================");


        log.info("===================================== Logging ProvisioningEntity ===============================");

        log.info("Logging Provisioning Entity Name : " + provisioningEntity.getEntityName());

        if (provisioningEntity.getAttributes() != null) {

            for (Map.Entry<ClaimMapping, List<String>> entry : provisioningEntity.getAttributes().entrySet()) {

                log.info("Logging Provisioning claim uri : " + entry.getKey().getLocalClaim().getClaimUri());
                log.info("Logging Provisioning values : ");
                for (String value : entry.getValue()) {
                    log.info("Logging Provisioning value : " + value);
                }
            }
        }

        log.info("===============================================================================================");


        // if there is no any provisioning identifier which is created for user by the external provisioning
        // we need to send null
        return null;
    }

}
