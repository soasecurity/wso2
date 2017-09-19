/*
 * Copyright soasecurity.org  All Rights Reserved.
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

import org.apache.commons.httpclient.contrib.ssl.EasySSLProtocolSocketFactory;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.HttpEntity;
import org.apache.http.HttpStatus;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.config.Registry;
import org.apache.http.config.RegistryBuilder;
import org.apache.http.conn.socket.ConnectionSocketFactory;
import org.apache.http.conn.socket.PlainConnectionSocketFactory;
import org.apache.http.conn.ssl.*;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.conn.PoolingHttpClientConnectionManager;
import org.apache.http.util.EntityUtils;
import org.json.JSONObject;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.model.RequestParameter;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.token.handlers.grant.AbstractAuthorizationGrantHandler;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.user.core.UserCoreConstants;

import javax.net.ssl.SSLContext;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;


/**
 * OpenAM Cookie grant type for Identity Server
 */
public class OpenAMCookieGrantHandler extends AbstractAuthorizationGrantHandler  {

    private static Log log = LogFactory.getLog(OpenAMCookieGrantHandler.class);

    static final String OPENAM_COOKIE_GRANT_PARAM = "cookie";

    static final String OPENAM_DOMAIN_NAME_PARAM = "domainName";

    private static String defaultDomainName = "PRIMARY";

    private static boolean ignoreSslValidation = true;

    private static String sessionInfoUrl = "http://localhost:8080/openam/json/realms/root/sessions/?_action=getSessionInfo";

    private static CloseableHttpClient httpClient;

    @Override
    public void init() throws IdentityOAuth2Exception {

        super.init();

        String endpointUrl = System.getProperty("OpenAM.Session.Endpoint");
        if(endpointUrl != null && endpointUrl.trim().length() > 0) {
            sessionInfoUrl = endpointUrl;
            log.info("Read OpenAM session endpoint from System properly :" + sessionInfoUrl);
        } else {
            endpointUrl = IdentityUtil.getProperty("OAuth.SupportedGrantTypes.SupportedGrantType.OpenAMSessionEndpoint");
            if (endpointUrl != null && endpointUrl.trim().length() > 0) {
                sessionInfoUrl = endpointUrl;
                log.info("Read OpenAM session endpoint from identity.xml file :" + sessionInfoUrl);
            } else {
                log.warn("OpenAM session endpoint is not configured and using default end point which is : " + sessionInfoUrl);
            }
        }

        String domainName = IdentityUtil.getProperty("OAuth.SupportedGrantTypes.SupportedGrantType.OpenAMDefaultDomainName");
        if(domainName != null && domainName.trim().length() > 0){
            defaultDomainName = domainName;
        } else {
            log.warn("OpenAM Domain name is not configured and using default end point which is : " + sessionInfoUrl);
        }

        String sslValidation = IdentityUtil.getProperty("OAuth.SupportedGrantTypes.SupportedGrantType.IgnoreSSLValidation");
        if(sslValidation != null && sslValidation.trim().length() > 0){
            ignoreSslValidation = Boolean.parseBoolean(sslValidation);
        } else {
            log.warn("Ignore SSL validation is not configured and using default end point which is : " + ignoreSslValidation);
        }


        SSLConnectionSocketFactory sslSocketFactory = null;

        if(ignoreSslValidation) {

            try {
                sslSocketFactory = new SSLConnectionSocketFactory(new EasySSLProtocolSocketFactory(),
                        SSLConnectionSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER);
            } catch (GeneralSecurityException e) {
                log.error(e);
            } catch (IOException e) {
                log.error(e);
            }
        } else {
            sslSocketFactory = SSLConnectionSocketFactory.getSocketFactory();
        }


        Registry<ConnectionSocketFactory> socketFactoryRegistry = RegistryBuilder.<ConnectionSocketFactory>create()
                .register("http", PlainConnectionSocketFactory.getSocketFactory())
                .register("https", sslSocketFactory)
                .build();


        PoolingHttpClientConnectionManager connectionManager = new PoolingHttpClientConnectionManager(socketFactoryRegistry);
        connectionManager.setMaxTotal(100);

        httpClient = HttpClients.custom().setConnectionManager(connectionManager).build();
    }

    @Override
    public boolean validateGrant(OAuthTokenReqMessageContext oAuthTokenReqMessageContext)  throws IdentityOAuth2Exception {

        log.debug("OpenAM Cookie grant handler is invoked");

        boolean authStatus = false;

        // extract request parameters
        RequestParameter[] parameters = oAuthTokenReqMessageContext.getOauth2AccessTokenReqDTO().getRequestParameters();

        String cookie = null;
        String username;
        String domainName = null;

        // find out mobile number
        for(RequestParameter parameter : parameters){
            if(OPENAM_COOKIE_GRANT_PARAM.equals(parameter.getKey())){
                if(parameter.getValue() != null && parameter.getValue().length > 0){
                    cookie = parameter.getValue()[0];
                }
            }
            if(OPENAM_DOMAIN_NAME_PARAM.equals(parameter.getKey())){
                if(parameter.getValue() != null && parameter.getValue().length > 0){
                    domainName = parameter.getValue()[0];
                }
            }
        }

        if (domainName == null || domainName.trim().length() == 0){
            domainName = defaultDomainName;
        } else {
            domainName = domainName.trim();
        }

        if(cookie != null) {
            username = validateAndRetrieveUser(cookie);
            if (username != null) {
                log.info("Validated Username : " + username);
                log.info("Domain Name : " + domainName);
                // if valid set authorized mobile number as grant user
                AuthenticatedUser user = OAuth2Util.getUserFromUserName(domainName +
                        UserCoreConstants.DOMAIN_SEPARATOR +username );
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
     * @param cookie OpenAM cookie
     * @return username which is related to given cookie
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

            if(log.isDebugEnabled()) {
                log.debug("Response from OpenAM Session endpoint : " + response);
            }

            JSONObject object = new JSONObject(response);

            if(status == HttpStatus.SC_OK) {
                log.debug("Authenticated OpenAM Cookie");
                username = (String) object.get("username");
            } else if (status == HttpStatus.SC_UNAUTHORIZED) {
                log.error("Unauthenticated OpenAM Cookie");
            } else {
                log.error("Unexpected Error.  Error code :" + status);
            }

        } catch (IOException e) {
            log.error("Unexpected Error", e);
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


    private static SSLContext buildSSLContext()
            throws NoSuchAlgorithmException, KeyManagementException,
            KeyStoreException {
        SSLContext sslcontext = SSLContexts.custom()
                .setSecureRandom(new SecureRandom())
                .loadTrustMaterial(null, new TrustStrategy() {

                    public boolean isTrusted(X509Certificate[] chain, String authType)
                            throws CertificateException {
                        return true;
                    }
                })
                .build();
        return sslcontext;
    }

}
