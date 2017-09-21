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
package org.soasecurity.wso2.apim.openam.cookie.authentication.handler;


import org.apache.axis2.context.MessageContext;
import org.apache.commons.httpclient.contrib.ssl.EasySSLProtocolSocketFactory;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.HttpEntity;

import org.apache.http.HttpStatus;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.config.Registry;
import org.apache.http.config.RegistryBuilder;
import org.apache.http.conn.socket.ConnectionSocketFactory;
import org.apache.http.conn.socket.PlainConnectionSocketFactory;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.conn.PoolingHttpClientConnectionManager;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;
import org.apache.synapse.ManagedLifecycle;
import org.apache.synapse.core.SynapseEnvironment;
import org.apache.synapse.core.axis2.Axis2MessageContext;
import org.apache.synapse.rest.AbstractHandler;
import org.json.JSONObject;

import org.soasecurity.wso2.apim.openam.cookie.authentication.handler.cache.ClientCookieTokenCache;


import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.util.*;


/**
 * APIM handler to validate cookie & generate an access token
 * <handler class="org.soasecurity.wso2.apim.openam.cookie.authentication.handler.OpenAMCookieAuthenticationHandler"/>
 * System properties
 * apim_client_header_name
 * openam_cookie_header_names
 * client_cookie_token_cache_validity_time
 */
public class OpenAMCookieAuthenticationHandler extends AbstractHandler implements ManagedLifecycle {


    private static CloseableHttpClient httpClient;

    private static final Log log = LogFactory.getLog(OpenAMCookieAuthenticationHandler.class);

    public void init(SynapseEnvironment synapseEnvironment) {

        SSLConnectionSocketFactory sslSocketFactory = null;
        try {
            sslSocketFactory = new SSLConnectionSocketFactory(new EasySSLProtocolSocketFactory(),
                    SSLConnectionSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER);
        } catch (GeneralSecurityException e) {
            log.error(e);
        } catch (IOException e) {
            log.error(e);
        }
        Registry<ConnectionSocketFactory> socketFactoryRegistry = RegistryBuilder.<ConnectionSocketFactory>create()
                .register("http", PlainConnectionSocketFactory.getSocketFactory())
                .register("https", sslSocketFactory)
                .build();


        PoolingHttpClientConnectionManager connectionManager = new PoolingHttpClientConnectionManager(socketFactoryRegistry);
        connectionManager.setMaxTotal(200);
        httpClient = HttpClients.custom().setConnectionManager(connectionManager).build();
    }

    @Override
    public void destroy() {

    }

    public boolean handleRequest(org.apache.synapse.MessageContext synpaseMessageContext) {

        MessageContext axis2MessageContext = ((Axis2MessageContext) synpaseMessageContext).getAxis2MessageContext();

        String clientId = getClientId(axis2MessageContext);
        String cookie = getOpenAMCookie(axis2MessageContext);

        if(cookie == null || clientId == null) {
            return true;
        }

        String token = ClientCookieTokenCache.getInstance().get(clientId + cookie);

        if (token == null) {
            token = getAccessToken(axis2MessageContext, clientId);
            if (token != null) {
                ClientCookieTokenCache.getInstance().put(clientId + cookie, token);
            }
        }

        if (token == null) {
            token = "-----This-is-a-dummy-token-from-custom-handler-----"; // dummy token to fail the request
        }

        TreeMap headers = (TreeMap) axis2MessageContext.getProperty("TRANSPORT_HEADERS");
        headers.put("Authorization", "Bearer " + token);


        return true;

    }

    public boolean handleResponse(org.apache.synapse.MessageContext messageContext) {
        return true;
    }

    private String getAccessToken(MessageContext axis2MessageContext, String clientId) {


        CloseableHttpResponse httpResponse = null;

        String httpsPort = System.getProperty("https.nio.port");

        HttpPost httpPost = new HttpPost("https://localhost:"+httpsPort+"/token");

        List<BasicNameValuePair> urlParameters = new ArrayList<BasicNameValuePair>();
        urlParameters.add(new BasicNameValuePair("grant_type", "openamcookie"));
        urlParameters.add(new BasicNameValuePair("client_id", clientId));
        urlParameters.add(new BasicNameValuePair("cookie", getOpenAMCookie(axis2MessageContext)));

        try {
            httpPost.setEntity(new UrlEncodedFormEntity(urlParameters));
        } catch (UnsupportedEncodingException e) {
           log.error("Can't generate /token request", e);
           return null;
        }

        int status = 0;
        String response = "UNKNOWN";

        try {

            httpResponse = httpClient.execute(httpPost);

            status = httpResponse.getStatusLine().getStatusCode();

            HttpEntity entity = httpResponse.getEntity();
            response = EntityUtils.toString(entity);

            if(status == HttpStatus.SC_OK) {
                JSONObject object = new JSONObject(response);
                return (String)object.get("access_token");
            } else {
                log.error("Unexpected Error.  HTTP Status code :" + status);
                log.error("Erroneous Response : " + response);
                log.error("Erroneous Cookie " + getOpenAMCookie(axis2MessageContext));  //TODO remove log in prod
            }

        } catch (Exception e) {
            log.error("Unexpected Error.  HTTP Status code :" + status);
            log.error("Erroneous Response : " + response);
            log.error("Erroneous Cookie " + getOpenAMCookie(axis2MessageContext));  //TODO remove log in prod
        } finally {
            try {
                if(httpResponse != null) {
                    httpResponse.close();
                }
            } catch (IOException e) {
                log.error(e);
            }
        }

        return null;
    }


    private String getClientId(MessageContext messageContext){

        TreeMap headers = (TreeMap) messageContext.getProperty("TRANSPORT_HEADERS");
        String header = (String) headers.get(getClientIdHeaderName());

        return header;

    }

    private String getOpenAMCookie(MessageContext messageContext){

        TreeMap headers = (TreeMap) messageContext.getProperty("TRANSPORT_HEADERS");
        Set<String> headersNames = getOpenAMCookieHeaderName();
        for(String header : headersNames) {
            String cookie = (String) headers.get(header);
            if(cookie != null){
                return cookie;
            }
        }

        return null;
    }

    private String getClientIdHeaderName(){
        String name = System.getenv("apim_client_header_name");
        if(name == null || name.trim().length() == 0){
            name = "APIMClientId";
        }
        return name;
    }

    private Set<String> getOpenAMCookieHeaderName(){
        Set<String> headersNames = new HashSet<String>();
        String names = System.getenv("openam_cookie_header_names");
        if(names != null && names.trim().length() > 0) {
            String[] nameArray = names.split(",");
            for(String name : nameArray){
                headersNames.add(name.trim());
            }
        } else {
            headersNames.add("Cookie");
        }
        return headersNames;
    }
}

