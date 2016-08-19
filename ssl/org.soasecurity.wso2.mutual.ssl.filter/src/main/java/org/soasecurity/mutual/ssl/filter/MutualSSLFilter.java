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


package org.soasecurity.mutual.ssl.filter;


import java.io.IOException;
import java.security.Principal;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * Servlet Filter implementation to exact the X509Certificate from the HTTP request.
 */
public class MutualSSLFilter implements Filter {
    
    private static Log log = LogFactory.getLog(MutualSSLFilter.class);

    @Override
	public void doFilter(ServletRequest request, ServletResponse response,
                         FilterChain chain) throws IOException, ServletException {

        log.debug("Mutual SSL Filter is invoked.");

        X509Certificate[] certs = (X509Certificate[])request.getAttribute("javax.servlet.request.X509Certificate");

        if(certs != null){

            // client certificate must be first certificate in the chain
            X509Certificate clientCert = certs[0];

            // encode certificate
            String certificateData = "";
            try {
                certificateData = new String (Base64.encodeBase64(clientCert.getEncoded()));
            } catch (CertificateEncodingException e) {
                log.error("Error while encoding the certificate", e);
            }

            Principal principal = clientCert.getSubjectDN();

            String subjectDN = principal.getName();

            log.debug("Mutual Authentication is success full with subject : " + subjectDN);

            // creating new wrapper to set a new parameter
            X509HTTPServletWrapper wrapper = new X509HTTPServletWrapper((HttpServletRequest)request, subjectDN,
                    certificateData);

            chain.doFilter(wrapper, response);


        } else {
            // fail the request as mutual authentication has not been happened at transport level
            log.error("Mutual SSL authentication is failed.");
            ((HttpServletResponse)response).sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
        }

	}

	@Override
    public void init(FilterConfig filterConfig) throws ServletException {
    }
    
	@Override
    public void destroy() {
    }

}
