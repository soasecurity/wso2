/*
 * Copyright (c) soasecurity.org All Rights Reserved.
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
package org.soasecurity.wso2.oauth2.openam.extended.cookie.grant;

import org.wso2.carbon.apimgt.keymgt.ScopesIssuer;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;

/**
 * Extended version of OpenAMCookieGrantValidator which can be used with WSO2 APIM
 */
public class ExtendedOpenAMCookieGrantHandler extends OpenAMCookieGrantHandler{

    @Override
    public boolean validateScope(OAuthTokenReqMessageContext tokReqMsgCtx) {

        return ScopesIssuer.getInstance().setScopes(tokReqMsgCtx);
    }

}
