/*
 *  Copyright (c) WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */


package org.soasecurity.wso2.mutual.auth.oauth2.client;

import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.HttpMethod;
import org.apache.commons.httpclient.NameValuePair;
import org.apache.commons.httpclient.methods.GetMethod;
import org.apache.commons.httpclient.methods.PostMethod;
import org.apache.http.HttpStatus;

import java.io.File;

/**
 * Mutual SSL client with Mutual SSL support
 */
public class MutualSSLOAuthClient {

    // currently two sample keystores are available  client.jks and wso2carbon.jks
    // wso2carbon.jks file is same keystore which is used in WSO2 products.

    private static String keyStoreName = "wso2carbon.jks";

    // password of client.jks is apache and wso2carbon.jks is wso2carbon
    private static String keyStorePassword = "wso2carbon";

    private static String endPoint = "https://localhost:9443/oauth2/token";

    public static void main(String[] args) throws Exception {

        File file = new File((new File(".")).getCanonicalPath() + File.separator + "src" +
                File.separator + "main" + File.separator + "resources" +  File.separator +
                "keystore" + File.separator + keyStoreName);


        if(!file.exists()){
            throw new Exception("Key Store file can not be found in " + file.getCanonicalPath());
        }

        //Set trust store, you need to import server's certificate of CA certificate chain in to this
        //key store
        System.setProperty("javax.net.ssl.trustStore", file.getCanonicalPath());
        System.setProperty("javax.net.ssl.trustStorePassword", keyStorePassword);

        //Set key store, this must contain the user private key
        //here we have use both trust store and key store as the same key store
        //But you can use a separate key store for key store an trust store.
        System.setProperty("javax.net.ssl.keyStore", file.getCanonicalPath());
        System.setProperty("javax.net.ssl.keyStorePassword", keyStorePassword);


        HttpClient client = new HttpClient();

        HttpMethod method = new PostMethod(endPoint);

        // Base64 encoded client id & secret
        method.setRequestHeader("Authorization", "Basic T09pN2dpUjUwdDZtUmU1ZkpmWUhVelhVa1QwYTpOOUI2dDZxQ0E2RFp2eTJPQkFIWDhjVlI1eUlh");
        method.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");

        NameValuePair pair1 = new NameValuePair();
        pair1.setName("grant_type");
        pair1.setValue("x509");

        NameValuePair pair2 = new NameValuePair();
        pair2.setName("username");
        pair2.setValue("asela");


        NameValuePair pair3 = new NameValuePair();
        pair3.setName("password");
        pair3.setValue("asela");

        method.setQueryString(new NameValuePair[] {pair1, pair2, pair3});

        int statusCode = client.executeMethod(method);

        if (statusCode != HttpStatus.SC_OK) {

            System.out.println("Failed: " + method.getStatusLine());

        } else {

            byte[] responseBody = method.getResponseBody();

            System.out.println(new String(responseBody));
        }
    }


}
