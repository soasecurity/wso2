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
package org.soasecurity.wso2.oauth2.openam.cookie.grant;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.HttpEntity;
import org.apache.http.HttpStatus;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.conn.PoolingHttpClientConnectionManager;
import org.apache.http.util.EntityUtils;
import org.json.JSONObject;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.model.RequestParameter;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.token.handlers.grant.AbstractAuthorizationGrantHandler;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

import java.io.IOException;


/**
 * X509 grant type for Identity Server
 */
public class OpenAMCookieGrantHandler extends AbstractAuthorizationGrantHandler  {

    private static Log log = LogFactory.getLog(OpenAMCookieGrantHandler.class);

    static final String OPENAM_COOKIE_GRANT_PARAM = "openamcookie";

    private static String sessionInfoUrl = "http://localhost:8080/openam/json/realms/root/sessions/?_action=getSessionInfo";

    private static CloseableHttpClient httpClient;

    @Override
    public void init() throws IdentityOAuth2Exception {
        super.init();

        PoolingHttpClientConnectionManager connectionManager = new PoolingHttpClientConnectionManager();
        connectionManager.setMaxTotal(100);

        httpClient = HttpClients.custom().setConnectionManager(connectionManager).build();
    }

    @Override
    public boolean validateGrant(OAuthTokenReqMessageContext oAuthTokenReqMessageContext)  throws IdentityOAuth2Exception {

        log.info("OpenAM Cookie grant handler is invoked");

        boolean authStatus = false;

        // extract request parameters
        RequestParameter[] parameters = oAuthTokenReqMessageContext.getOauth2AccessTokenReqDTO().getRequestParameters();

        String cookie = null;
        String username = null;

        // find out mobile number
        for(RequestParameter parameter : parameters){
            if(OPENAM_COOKIE_GRANT_PARAM.equals(parameter.getKey())){
                if(parameter.getValue() != null && parameter.getValue().length > 0){
                    cookie = parameter.getValue()[0];
                }
            }
        }

        if(cookie != null) {

            username = validateAndRetrieveUser(cookie);

            if (username != null) {
                log.info("Validated Username : " + username);
                // if valid set authorized mobile number as grant user
                AuthenticatedUser user = OAuth2Util.getUserFromUserName(username);
                user.setAuthenticatedSubjectIdentifier(user.toString());
                oAuthTokenReqMessageContext.setAuthorizedUser(user);
                oAuthTokenReqMessageContext.setScope(oAuthTokenReqMessageContext.getOauth2AccessTokenReqDTO().getScope());
                authStatus = true;
            }
        } else {
            log.error("OpenAM Cookie is not available");
        }

        return authStatus;
    }


    /**
     *
     * @param cookie
     * @return
     */
    protected String validateAndRetrieveUser(String cookie){

        String username = null;
        CloseableHttpResponse httpResponse = null;

        HttpPost httpPost = new HttpPost(sessionInfoUrl);
        httpPost.setHeader("iplanetDirectoryPro", cookie);
        httpPost.setHeader("Content-Type", "application/json");

        try {

            httpResponse = httpClient.execute(httpPost);

            int status = httpResponse.getStatusLine().getStatusCode();

            HttpEntity entity = httpResponse.getEntity();
            String response = EntityUtils.toString(entity);

            log.info("Response : " + response);

            JSONObject object = new JSONObject(response);

            if(status == HttpStatus.SC_OK) {
                log.info("Authenticated Cookie");
                username = (String) object.get("username");
            } else if (status == HttpStatus.SC_UNAUTHORIZED) {
                log.error("Unauthenticated Cookie");
            } else {
                log.error("Unexpected Error.  Error code :" + status);
            }

        } catch (IOException e) {
            log.error(e);
        } finally {
            try {
                if(httpResponse != null) {
                    httpResponse.close();
                }
            } catch (IOException e) {
                log.error(e);
            }
        }
        return username;

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
