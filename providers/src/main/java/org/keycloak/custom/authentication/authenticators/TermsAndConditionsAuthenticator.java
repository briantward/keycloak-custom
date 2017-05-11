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

import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.*;

import java.util.HashSet;
import java.util.Set;

/**
 * @author <a href="mailto:bward@redhat.com">Brian Ward</a>
 * @version $Revision: 1 $
 */
public class TermsAndConditionsAuthenticator implements Authenticator {

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        Set<Integer> tacIds = new HashSet<>();

        String accceptanceTimestampString = context.getUser().getFirstAttribute("terms_and_conditions");

        Long acceptanceTimestamp = Long.getLong("");

        RealmModel realm = context.getRealm();
        String realmTacIdString = realm.getAttribute("REALM_TAC");
        if (realmTacIdString != null) {
            Integer realmTacId = new Integer(realmTacIdString);
            tacIds.add(realmTacId);
        }

        ClientModel client = context.getClientSession().getClient();
        String clientTacIdString = client.getAttribute("CLIENT_TAC");
        if (clientTacIdString != null) {
            Integer clientTacId = new Integer(clientTacIdString);
            tacIds.add(clientTacId);
        }


        // TAC by Roles not possible this way since no attributes per role
        // Set<RoleModel> userRoles = context.getUser().getRoleMappings();



    }

    @Override
    public void action(AuthenticationFlowContext context) {

    }

    @Override
    public boolean requiresUser() {
        return false;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return false;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {

    }

    @Override
    public void close() {

    }
}
