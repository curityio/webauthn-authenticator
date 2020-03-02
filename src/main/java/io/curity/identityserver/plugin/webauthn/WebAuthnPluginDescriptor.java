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

import com.google.common.collect.ImmutableMap;
import io.curity.identityserver.plugin.webauthn.authenticate.WebAuthnAuthenticationRequestHandler;
import io.curity.identityserver.plugin.webauthn.authenticate.WebAuthnAuthenticationValidationRequestHandler;
import io.curity.identityserver.plugin.webauthn.authenticate.WebAuthnSelectDeviceRequestHandler;
import io.curity.identityserver.plugin.webauthn.autologin.WebAuthtnContinueWithAutoLoginRequestHandler;
import io.curity.identityserver.plugin.webauthn.register.WebAuthnRegistrationRequestHandler;
import se.curity.identityserver.sdk.authentication.AnonymousRequestHandler;
import se.curity.identityserver.sdk.authentication.AuthenticatorRequestHandler;
import se.curity.identityserver.sdk.authentication.RegistrationRequestHandler;
import se.curity.identityserver.sdk.plugin.descriptor.AuthenticatorPluginDescriptor;
import se.curity.identityserver.sdk.service.AutoLoginManager;

import java.util.Collections;
import java.util.Map;

public final class WebAuthnPluginDescriptor implements AuthenticatorPluginDescriptor<WebAuthnPluginConfiguration>
{
    private static final String INDEX = "index";
    public static final String SELECT_DEVICE = "select-device";
    public static final String VALIDATION = "validate";

    @Override
    public String getPluginImplementationType()
    {
        return "webauthn";
    }

    @Override
    public Map<String, Class<? extends AuthenticatorRequestHandler<?>>> getAuthenticationRequestHandlerTypes()
    {
        return ImmutableMap.of(
                INDEX, WebAuthnAuthenticationRequestHandler.class,
                SELECT_DEVICE, WebAuthnSelectDeviceRequestHandler.class,
                VALIDATION, WebAuthnAuthenticationValidationRequestHandler.class
        );
    }

    @Override
    public Map<String, Class<? extends RegistrationRequestHandler<?>>> getRegistrationRequestHandlerTypes()
    {
        return Collections.singletonMap(INDEX, WebAuthnRegistrationRequestHandler.class);
    }

    @Override
    public Map<String, Class<? extends AnonymousRequestHandler<?>>> getAnonymousRequestHandlerTypes()
    {
        return ImmutableMap.of(
                AutoLoginManager.PATH_CONFIRM_CONTINUE, WebAuthtnContinueWithAutoLoginRequestHandler.class
        );
    }

    @Override
    public Class<? extends WebAuthnPluginConfiguration> getConfigurationType()
    {
        return WebAuthnPluginConfiguration.class;
    }
}
