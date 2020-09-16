/*
 *  Copyright 2020 Curity AB
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package io.curity.identityserver.plugin.webauthn;

import com.google.common.collect.ImmutableSet;
import se.curity.identityserver.sdk.Nullable;
import se.curity.identityserver.sdk.attribute.Attribute;
import se.curity.identityserver.sdk.service.ExceptionFactory;
import se.curity.identityserver.sdk.service.SessionManager;

import java.util.Set;
import java.util.UUID;

import static se.curity.identityserver.sdk.errors.ErrorCode.INVALID_INPUT;

/**
 * Represents an immutable pair with the WebAuthn authentication session ID and the username that was used to start it.
 */
public class WebAuthnAuthenticationSession
{
    private static final String WEBAUTHN_SESSION_DATA_PREFIX = "webauthn_";
    static final String WEBAUTHN_USERNAME_KEY = "webauthn_username";
    static final String WEBAUTHN_SESSION_ID_KEY = "webauthn_session_id";
    static final Set<String> webAuthnSessionKeys = ImmutableSet.of(WEBAUTHN_SESSION_ID_KEY, WEBAUTHN_USERNAME_KEY);
    private final String _username;
    private final String _sessionId;

    WebAuthnAuthenticationSession(String username,
                                  String sessionId)
    {
        _username = username;
        _sessionId = sessionId;
    }

    // TODO Add devices?
    public static void createAndSave(String username,
                                     SessionManager sessionManager)
    {
        // Clear previous session before creating a new one
        clear(sessionManager);
        String sessionId = UUID.randomUUID().toString();

        sessionManager.put(Attribute.of(WEBAUTHN_USERNAME_KEY, username));
        sessionManager.put(Attribute.of(WEBAUTHN_SESSION_ID_KEY, sessionId));

        WebAuthnAuthenticationSession WebAuthAuthenticationSession = new WebAuthnAuthenticationSession(username,
                sessionId);
    }

    public static WebAuthnAuthenticationSession readFromSession(SessionManager sessionManager,
                                                                ExceptionFactory exceptionFactory)
    {
        @Nullable
        Attribute sessionId = sessionManager.get(WEBAUTHN_SESSION_ID_KEY);
        @Nullable
        Attribute username = sessionManager.get(WEBAUTHN_USERNAME_KEY);

        if (sessionId != null && username != null)
        {
            return new WebAuthnAuthenticationSession(username.getValueOfType(String.class),
                    sessionId.getValueOfType(String.class));
        }

        throw exceptionFactory.badRequestException(INVALID_INPUT);
    }

    private static void clear(SessionManager sessionManager)
    {
        webAuthnSessionKeys.forEach(sessionManager::remove);
    }

    public String getUsername()
    {
        return _username;
    }

    public String getSessionId()
    {
        return _sessionId;
    }
}
