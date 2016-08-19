/*
 * Copyright (c) WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
package org.soasecurity.wso2.oauth2.x509.grant;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.model.RequestParameter;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.token.handlers.grant.AbstractAuthorizationGrantHandler;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import sun.security.x509.X509CertImpl;

import java.security.Principal;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

/**
 * X509 grant type for Identity Server
 */
public class X509GrantHandler extends AbstractAuthorizationGrantHandler  {

    private static Log log = LogFactory.getLog(X509GrantHandler.class);


    public static final String X509_GRANT_PARAM = "x509";

    @Override
    public boolean validateGrant(OAuthTokenReqMessageContext oAuthTokenReqMessageContext)  throws IdentityOAuth2Exception {

        log.info("X.509 Grant handler is invoked");

        boolean authStatus = false;

        // extract request parameters
        RequestParameter[] parameters = oAuthTokenReqMessageContext.getOauth2AccessTokenReqDTO().getRequestParameters();

        String certParam = null;
        String subjectDN = null;

        // find out mobile number
        for(RequestParameter parameter : parameters){
            if(X509_GRANT_PARAM.equals(parameter.getKey())){
                if(parameter.getValue() != null && parameter.getValue().length > 0){
                    certParam = parameter.getValue()[0];
                }
            } else if("subjectDN".equalsIgnoreCase(parameter.getKey())) {
                if(parameter.getValue() != null && parameter.getValue().length > 0){
                    subjectDN = parameter.getValue()[0];
                }
            }
        }

        String username = null;

        if(subjectDN != null) {
            username = subjectDN;
            log.info("Username is retrieved from Subject DN : " + username);
        } else {
            if (certParam != null) {
                //validate certificate number
                username = validCertificate(certParam);
                log.info("Username is retrieved from Certificate : " + username);
            }
        }

        if(username != null) {
            // if valid set authorized mobile number as grant user
            AuthenticatedUser user = OAuth2Util.getUserFromUserName(username);
            user.setAuthenticatedSubjectIdentifier(user.toString());
            oAuthTokenReqMessageContext.setAuthorizedUser(user);
            oAuthTokenReqMessageContext.setScope(oAuthTokenReqMessageContext.getOauth2AccessTokenReqDTO().getScope());
            authStatus = true;
        }

        return authStatus;
    }


    /**
     * TODO
     *
     * You need to implement how to validate the certificate
     *
     * @param certificate
     * @return
     */
    protected String validCertificate(String certificate){

        // just demo validation


        // retrieve the certificate object
        byte[] byteArray = Base64.decodeBase64(certificate);

        try {
            X509Certificate x509Certificate = new X509CertImpl(byteArray);

            Principal principal = x509Certificate.getSubjectDN();

            String subjectDN = principal.getName();

            if(subjectDN.contains("CN=soasecurity.org")) {
                // username related to the certificate
                return "asela";
            }

        } catch (CertificateException e) {
            log.error(e);
        }

        return null;
    }

    public boolean authorizeAccessDelegation(OAuthTokenReqMessageContext tokReqMsgCtx)
            throws IdentityOAuth2Exception {

        return true;

    }


    public boolean validateScope(OAuthTokenReqMessageContext tokReqMsgCtx)
            throws IdentityOAuth2Exception {

        return true;
    }

}
