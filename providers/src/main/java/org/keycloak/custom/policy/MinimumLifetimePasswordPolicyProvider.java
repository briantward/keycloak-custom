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

package org.keycloak.custom.policy;

import org.jboss.logging.Logger;
import org.keycloak.credential.CredentialModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.PasswordPolicy;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.policy.PasswordPolicyProvider;
import org.keycloak.policy.PolicyError;

import java.time.Instant;
import java.util.List;

/**
 * @author <a href="mailto:bward@redhat.com">Brian Ward</a>a>
 */
public class MinimumLifetimePasswordPolicyProvider implements PasswordPolicyProvider {

    private static final Logger logger = Logger.getLogger(MinimumLifetimePasswordPolicyProvider.class);
    private static final String ERROR_MESSAGE = "invalidPasswordMinLifetimeMessage";
    public static final String PASSWORD_POLICY_ID = "passwordMinLifetime";

    private KeycloakSession session;

    public MinimumLifetimePasswordPolicyProvider(KeycloakSession session) {
        this.session = session;
    }

    @Override
    public PolicyError validate(RealmModel realm, UserModel user, String password) {
        PasswordPolicy policy = session.getContext().getRealm().getPasswordPolicy();
        int passwordMinLifePolicyValue = policy.getPolicyConfig(PASSWORD_POLICY_ID);
        if (passwordMinLifePolicyValue != -1) {
            List<CredentialModel> storedPasswords = session.userCredentialManager().getStoredCredentialsByType(realm, user, CredentialModel.PASSWORD);
            for (CredentialModel cred : storedPasswords) {
                Long createDate = cred.getCreatedDate();
                if (createDate !=null && Instant.now().isBefore(Instant.ofEpochMilli(createDate).plusSeconds(passwordMinLifePolicyValue))){
                    return new PolicyError(ERROR_MESSAGE, passwordMinLifePolicyValue);
                }
            }
        }
        return null;
    }

    @Override
    public PolicyError validate(String user, String password) {
        return null;
    }

    @Override
    public Object parseConfig(String value) {
        return value != null ? Integer.parseInt(value) : MinimumLifetimePasswordPolicyProviderFactory.DEFAULT_VALUE;
    }

    @Override
    public void close() {

    }
}
