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
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.provisioning.AbstractOutboundProvisioningConnector;
import org.wso2.carbon.identity.provisioning.AbstractProvisioningConnectorFactory;
import org.wso2.carbon.identity.provisioning.IdentityProvisioningException;

import java.util.ArrayList;
import java.util.List;

public class CustomProvisioningConnectorFactory extends AbstractProvisioningConnectorFactory {

    private static final Log log = LogFactory.getLog(CustomProvisioningConnectorFactory.class);
    private static final String SOASECURITY = "SOASecurity";

    @Override
    protected AbstractOutboundProvisioningConnector buildConnector(Property[] provisioningProperties)
                                                                                throws IdentityProvisioningException {
        CustomProvisioningConnector connector = new CustomProvisioningConnector();
        connector.init(provisioningProperties);

        if (log.isDebugEnabled()) {
            log.debug("SOASecurity provisioning connector created successfully.");
        }

        return connector;
    }

    @Override
    public String getConnectorType() {
        return SOASECURITY;
    }


    public List<Property> getConfigurationProperties() {

        List<Property> properties = new ArrayList<Property>();

        Property urlProperty = new Property();
        urlProperty.setName(CustomProvisioningConnectorConstants.PROPERTY_NAME_URL);
        urlProperty.setDisplayName("Enter URL Property");
        urlProperty.setDescription("This is sample URL Property");
        urlProperty.setDefaultValue("http://soasecurity.org");
        urlProperty.setRequired(true);

        Property usernameProperty = new Property();
        usernameProperty.setName(CustomProvisioningConnectorConstants.PROPERTY_NAME_USERNAME);
        usernameProperty.setDisplayName("Enter UserName");


        Property passwordProperty = new Property();
        passwordProperty.setName(CustomProvisioningConnectorConstants.PROPERTY_NAME_PASSWORD);
        passwordProperty.setDisplayName("Enter Password");
        passwordProperty.setConfidential(true);

        properties.add(urlProperty);
        properties.add(usernameProperty);
        properties.add(passwordProperty);

        return properties;
    }

}
