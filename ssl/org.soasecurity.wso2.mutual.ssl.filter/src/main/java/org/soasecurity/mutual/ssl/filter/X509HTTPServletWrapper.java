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

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import java.util.*;

/**
 * Custom wrapper to set parameters
 */
public class X509HTTPServletWrapper extends HttpServletRequestWrapper {

    private String subjectDN;

    private String x509;

    private Enumeration<String> parameterNames;


    public X509HTTPServletWrapper(HttpServletRequest request, String subjectDN, String x509) {

        super(request);

        this.subjectDN = subjectDN;

        //add new parameter to name list
        Set<String> parameterNameSet = new HashSet<String>();
        Enumeration<String> requestParameterNames = request.getParameterNames();
        while (requestParameterNames.hasMoreElements()) {
            parameterNameSet.add(requestParameterNames.nextElement());
        }
        parameterNameSet.add("subjectDN");
        parameterNameSet.add("x509");

        this.x509 = x509;
        this.parameterNames = Collections.enumeration(parameterNameSet);


    }

    @Override
    public String getParameter(String name) {

        if("subjectDN".equalsIgnoreCase(name)){
            return subjectDN;
        }

        if("x509".equalsIgnoreCase(name)){
            return x509;
        }

        return super.getParameter(name);
    }

    @Override
    public Enumeration<String> getParameterNames() {
        return this.parameterNames;
    }

    @Override
    public String[] getParameterValues(String name) {

        if("subjectDN".equalsIgnoreCase(name)){
            return new String[]{ subjectDN };
        }

        if("x509".equalsIgnoreCase(name)){
            return new String[]{ x509 };
        }

        return super.getParameterValues(name);
    }
}
