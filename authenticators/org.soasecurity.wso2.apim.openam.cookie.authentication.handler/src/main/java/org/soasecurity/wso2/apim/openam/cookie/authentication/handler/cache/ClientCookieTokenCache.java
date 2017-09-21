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

package org.soasecurity.wso2.apim.openam.cookie.authentication.handler.cache;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.caching.impl.CachingConstants;
import org.wso2.carbon.utils.CarbonUtils;

import javax.cache.*;
import java.util.concurrent.TimeUnit;

/**
 * Local cache to keep cookie to token mapping
 */
public class ClientCookieTokenCache {

    private static final String COOKIE_TOKEN_CACHE_MANAGER = "COOKIE_TOKEN_CACHE_MANAGER";
    private static final String COOKIE_TOKEN_ENGINE_CACHE =
            CachingConstants.LOCAL_CACHE_PREFIX + "COOKIE_TOKEN_ENGINE_CACHE";

    private static Log log = LogFactory.getLog(ClientCookieTokenCache.class);

    private static volatile ClientCookieTokenCache instance;

    private CacheBuilder<String, String> cacheBuilder;


    private ClientCookieTokenCache() {
        getCookieTokenCache();
    }

    public static ClientCookieTokenCache getInstance() {
        CarbonUtils.checkSecurity();
        if (instance == null) {
            synchronized (ClientCookieTokenCache.class) {
                if (instance == null) {
                    instance = new ClientCookieTokenCache();
                }
            }
        }
        return instance;
    }

    private Cache<String, String> getCookieTokenCache() {

        Cache<String, String> cache;
        CacheManager cacheManager = Caching.getCacheManagerFactory().getCacheManager(COOKIE_TOKEN_CACHE_MANAGER);
        if (cacheManager != null) {
            if (cacheBuilder == null) {
                cacheManager.removeCache(COOKIE_TOKEN_ENGINE_CACHE);

                int validityTime = 900;
                String validityTimeSting = System.getenv("client_cookie_token_cache_validity_time");
                if(validityTimeSting != null && validityTimeSting.trim().length() > 0){
                    validityTime = Integer.parseInt(validityTimeSting);
                }

                cacheBuilder = cacheManager.<String, String>createCacheBuilder(COOKIE_TOKEN_ENGINE_CACHE).
                        setExpiry(CacheConfiguration.ExpiryType.ACCESSED,
                                new CacheConfiguration.Duration(TimeUnit.SECONDS, 600)).
                        setExpiry(CacheConfiguration.ExpiryType.MODIFIED,
                                new CacheConfiguration.Duration(TimeUnit.SECONDS, validityTime));
                cache = cacheBuilder.build();
            } else {
                cache = cacheManager.getCache(COOKIE_TOKEN_ENGINE_CACHE);
            }
        } else {
            cache = Caching.getCacheManager().getCache(COOKIE_TOKEN_ENGINE_CACHE);
        }

        return cache;
    }


    public String get(String clientCookie) {
        return getCookieTokenCache().get(clientCookie);
    }

    public void put(String clientCookie, String token) {
        getCookieTokenCache().put(clientCookie, token);
    }

}
