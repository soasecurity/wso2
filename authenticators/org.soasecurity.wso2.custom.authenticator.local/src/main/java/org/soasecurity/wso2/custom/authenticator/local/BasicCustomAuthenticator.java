/*
 * Copyright (c) 2014, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
package org.soasecurity.wso2.custom.authenticator.local;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.soasecurity.wso2.custom.authenticator.local.internal.BasicCustomAuthenticatorServiceComponent500;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.exception.InvalidCredentialsException;
import org.wso2.carbon.identity.application.authenticator.basicauth.BasicAuthenticator;
import org.wso2.carbon.identity.application.authenticator.basicauth.BasicAuthenticatorConstants;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Username Password based Authenticator
 */
public class BasicCustomAuthenticator extends BasicAuthenticator {

    private static final long serialVersionUID = 4345354156955223654L;
    private static final Log log = LogFactory.getLog(BasicCustomAuthenticator.class);


    @Override
    protected void processAuthenticationResponse(HttpServletRequest request,
                                                 HttpServletResponse response, AuthenticationContext context)
            throws AuthenticationFailedException {

        // call Basic Authenticator
        super.processAuthenticationResponse(request, response, context);

        //  get authenticated usernae
        String username = context.getSubject();

        boolean authorization = false;


        if("oidc".equalsIgnoreCase(context.getRequestType())) {

            // authorization only for openid connect requests

            try {

                int tenantId = BasicCustomAuthenticatorServiceComponent500.getRealmService().getTenantManager().
                        getTenantId(MultitenantUtils.getTenantDomain(username));
                UserStoreManager userStoreManager = (UserStoreManager) BasicCustomAuthenticatorServiceComponent500.getRealmService().
                        getTenantUserRealm(tenantId).getUserStoreManager();

                // verify user is assigned to role
                authorization = ((AbstractUserStoreManager) userStoreManager).isUserInRole(username, "openidConnectRole");
            } catch (UserStoreException e) {
                log.error(e);
            } catch (org.wso2.carbon.user.api.UserStoreException e) {
                log.error(e);
            }
        } else if("samlsso".equalsIgnoreCase(context.getRequestType()) && "soasecurity.org".equalsIgnoreCase(context.getRelyingParty())) {

            // authorization only for samlsso requests which are generated from SOASecurity service provider.

            try {

                int tenantId = BasicCustomAuthenticatorServiceComponent500.getRealmService().getTenantManager().
                        getTenantId(MultitenantUtils.getTenantDomain(username));
                UserStoreManager userStoreManager = (UserStoreManager) BasicCustomAuthenticatorServiceComponent500.getRealmService().
                        getTenantUserRealm(tenantId).getUserStoreManager();

                // retrieve email attribute of user
                String email = userStoreManager.getUserClaimValue(username, "http://wso2.org/claims/emailaddress", null);
                if(email.endsWith("soasecurity.org")){
                    authorization =  true;
                }
            } catch (UserStoreException e) {
                log.error(e);
            } catch (org.wso2.carbon.user.api.UserStoreException e) {
                log.error(e);
            }
        } else {
            // others scenarios are not verified.
            authorization = true;
        }

        if(!authorization) {
            log.error("user authorization is failed.");
            throw new InvalidCredentialsException();
        }
    }


    @Override
    public String getFriendlyName() {
        return BasicCustomAuthenticatorConstants.AUTHENTICATOR_FRIENDLY_NAME;
    }

    @Override
    public String getName() {
        return BasicCustomAuthenticatorConstants.AUTHENTICATOR_NAME;
    }
}