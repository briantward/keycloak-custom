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
package org.keycloak.custom.authentication.credentialprovider;

import org.keycloak.common.util.Time;
import org.keycloak.credential.*;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserCredentialModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.cache.CachedUserModel;
import org.keycloak.models.cache.OnUserCache;

import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @author <a href="mailto:bward@redhat.com">Brian Ward</a>
 * @version $Revision: 1 $
 */
public class SecretQuestionCredentialProvider implements CredentialProvider, CredentialInputValidator, CredentialInputUpdater, OnUserCache {
    public static final String SECRET_QUESTION = "SECRET_QUESTION";
    public static final String CACHE_KEY_BASE = SecretQuestionCredentialProvider.class.getName() + "." + SECRET_QUESTION;

    protected KeycloakSession session;

    public SecretQuestionCredentialProvider(KeycloakSession session) {
        this.session = session;
    }

    public CredentialModel getSecret(RealmModel realm, UserModel user, String questionId) {
        CredentialModel secret = null;
        if (user instanceof CachedUserModel) {
            CachedUserModel cached = (CachedUserModel)user;
            secret = (CredentialModel)cached.getCachedWith().get(CACHE_KEY_BASE + questionId);

        } else {
            secret = getSecretQuestionCredential(realm, user, questionId);
        }
        return secret;
    }

    private CredentialModel getSecretQuestionCredential(RealmModel realm, UserModel user, String questionId){
        List<CredentialModel> creds = session.userCredentialManager().getStoredCredentialsByType(realm, user, SECRET_QUESTION);
        if (!creds.isEmpty()){
            List<CredentialModel> filteredCreds = creds.stream().filter(cred -> cred.getDevice().equals(questionId)).collect(Collectors.toList());
            if (filteredCreds.size()==1) {
                return filteredCreds.get(0);
            }
        }
        // TODO make nice exception
        throw new RuntimeException("Invalid number of credentials found!");
    }

    @Override
    public boolean updateCredential(RealmModel realm, UserModel user, CredentialInput input) {
        if (!SECRET_QUESTION.equals(input.getType())) return false;
        if (!(input instanceof UserCredentialModel)) return false;
        UserCredentialModel credInput = (UserCredentialModel) input;
        List<CredentialModel> creds = session.userCredentialManager().getStoredCredentialsByType(realm, user, SECRET_QUESTION);
        if (creds.isEmpty()) {
            CredentialModel secret = new CredentialModel();
            secret.setType(SECRET_QUESTION);
            secret.setValue(credInput.getValue());
            secret.setCreatedDate(Time.currentTimeMillis());
            // to store multiple secret questions, the question is stored as device
            secret.setDevice(credInput.getDevice());
            session.userCredentialManager().createCredential(realm ,user, secret);
        } else {
            // find the answer to the correct security question
            // TODO review for NPE
            List<CredentialModel> filteredCreds = creds.stream()
                    .filter(credentialModel -> credentialModel.getDevice().equals(credInput.getDevice()))
                    .collect(Collectors.toList());
            if (filteredCreds.size()==1){
                filteredCreds.get(0).setValue(credInput.getValue());
                session.userCredentialManager().updateCredential(realm, user, creds.get(0));
            }
            else {
                // TODO make nice exception
                throw new RuntimeException("Invalid number of credentials found!");
            }
        }
        session.userCache().evict(realm, user);
        return true;
    }

    @Override
    public void disableCredentialType(RealmModel realm, UserModel user, String credentialType) {
        if (!SECRET_QUESTION.equals(credentialType)) return;
        session.userCredentialManager().disableCredentialType(realm, user, credentialType);
        session.userCache().evict(realm, user);

    }

    @Override
    public Set<String> getDisableableCredentialTypes(RealmModel realm, UserModel user) {
        if (!session.userCredentialManager().getStoredCredentialsByType(realm, user, SECRET_QUESTION).isEmpty()) {
            Set<String> set = new HashSet<>();
            set.add(SECRET_QUESTION);
            return set;
        } else {
            return Collections.EMPTY_SET;
        }

    }

    @Override
    public boolean supportsCredentialType(String credentialType) {
        return SECRET_QUESTION.equals(credentialType);
    }

    @Override
    public boolean isConfiguredFor(RealmModel realm, UserModel user, String credentialType) {
        if (!SECRET_QUESTION.equals(credentialType)) return false;
        return !session.userCredentialManager().getStoredCredentialsByType(realm, user, SECRET_QUESTION).isEmpty();
    }

    @Override
    public boolean isValid(RealmModel realm, UserModel user, CredentialInput input) {
        if (!SECRET_QUESTION.equals(input.getType())) return false;
        if (!(input instanceof UserCredentialModel)) return false;

        String secret = getSecret(realm, user, ((UserCredentialModel) input).getDevice()).getValue();

        return secret != null && ((UserCredentialModel)input).getValue().equals(secret);
    }

    @Override
    public void onCache(RealmModel realm, CachedUserModel user, UserModel delegate) {
        List<CredentialModel> creds = session.userCredentialManager().getStoredCredentialsByType(realm, user, SECRET_QUESTION);
        // go ahead and cache all the questions
        // again, cred.device is storing questionId
        if (!creds.isEmpty()) {
            creds.stream().forEach(cred -> user.getCachedWith().put(CACHE_KEY_BASE + cred.getDevice(), cred));
        }
    }
}
