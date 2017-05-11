/*
 * Copyright 2017 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.keycloak.custom.authentication.authenticators;

import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.Authenticator;
import org.keycloak.jose.jws.JWSBuilder;
import org.keycloak.models.*;
import org.keycloak.services.util.CookieHelper;

import javax.ws.rs.core.Cookie;
import javax.ws.rs.core.MultivaluedMap;
import java.net.URI;
import java.security.PrivateKey;

/**
 * @author <a href="mailto:bward@redhat.com">Brian Ward</a>
 * @version $Revision: 1 $
 */
public class UserAgentCookieAuthenticator implements Authenticator {

    private static final Logger logger = Logger.getLogger(UserAgentCookieAuthenticator.class);
    public static final String USER_AGENT_COOKIE_NAME = "KC_USER_AGENT";

    protected boolean validateCookie(AuthenticationFlowContext context) {
        Cookie cookie = context.getHttpRequest().getHttpHeaders().getCookies().get(USER_AGENT_COOKIE_NAME);
        if (cookie != null) {
            String encryptedToken = getUserAgentId(context);
            String encryptedCookieValue = cookie.getValue();
            if (encryptedCookieValue!=null && encryptedCookieValue.equals(encryptedToken)){
                logger.debug(USER_AGENT_COOKIE_NAME + " cookie is set and valid.");
            }
        }
        return false;
    }

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        if (validateCookie(context)) {
            context.success();
        }
    }

    @Override
    public void action(AuthenticationFlowContext context) {

    }

    protected String encryptToken(String value, PrivateKey key){
        return new JWSBuilder().jsonContent(value).rsa256(key);
    }

    protected String getUserAgentId(AuthenticationFlowContext context){
        MultivaluedMap<String, String> headers = context.getHttpRequest().getHttpHeaders().getRequestHeaders();
        String username = context.getUser().getUsername();
        String userAgent = headers.getFirst("User-Agent");
        String userIP = headers.getFirst("X-Forwarded-For");
        if (userIP == null){
            userIP = headers.getFirst("Remote-Addr");
        }
        return username + "_" + userIP + "_" +userAgent;
    }

    protected void setCookie(AuthenticationFlowContext context) {
        AuthenticatorConfigModel config = context.getAuthenticatorConfig();
        int maxCookieAge = 60 * 60 * 24 * 30; // 30 days
        if (config != null) {
            maxCookieAge = Integer.valueOf(config.getConfig().get("cookie.max.age"));
        }
        URI uri = context.getUriInfo().getBaseUriBuilder().path("realms").path(context.getRealm().getName()).build();

        PrivateKey key = context.getSession().keys().getActiveRsaKey(context.getRealm()).getPrivateKey();
        String userAgentId = getUserAgentId(context);
        String encryptedValue = encryptToken(userAgentId, key);

        CookieHelper.addCookie(USER_AGENT_COOKIE_NAME, encryptedValue,
                uri.getRawPath(),
                null, null,
                maxCookieAge,
                false, true);
    }

    @Override
    public boolean requiresUser() {
        return true;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {

    }

    @Override
    public void close() {

    }
}
