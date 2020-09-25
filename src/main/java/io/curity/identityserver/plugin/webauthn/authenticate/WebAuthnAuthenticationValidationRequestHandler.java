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

package io.curity.identityserver.plugin.webauthn.authenticate;

import io.curity.identityserver.plugin.webauthn.WebAuthnAuthenticationSession;
import io.curity.identityserver.plugin.webauthn.WebAuthnAuthenticatorLogic;
import io.curity.identityserver.plugin.webauthn.WebAuthnPluginConfiguration;
import io.curity.identityserver.plugin.webauthn.authenticate.WebAuthnAuthenticationValidationRequestModel.Post;
import se.curity.identityserver.sdk.Nullable;
import se.curity.identityserver.sdk.attribute.AccountAttributes;
import se.curity.identityserver.sdk.attribute.AuthenticationAttributes;
import se.curity.identityserver.sdk.attribute.ContextAttributes;
import se.curity.identityserver.sdk.attribute.SubjectAttributes;
import se.curity.identityserver.sdk.attribute.scim.v2.extensions.Device;
import se.curity.identityserver.sdk.authentication.AuthenticationResult;
import se.curity.identityserver.sdk.authentication.AuthenticatorRequestHandler;
import se.curity.identityserver.sdk.service.AccountManager;
import se.curity.identityserver.sdk.service.ExceptionFactory;
import se.curity.identityserver.sdk.service.SessionManager;
import se.curity.identityserver.sdk.web.Request;
import se.curity.identityserver.sdk.web.Response;

import java.util.Collections;
import java.util.List;
import java.util.Optional;

import static io.curity.identityserver.plugin.webauthn.WebAuthnPluginDescriptor.SELECT_DEVICE;
import static se.curity.identityserver.sdk.web.Response.ResponseModelScope.FAILURE;
import static se.curity.identityserver.sdk.web.ResponseModel.templateResponseModel;

public final class WebAuthnAuthenticationValidationRequestHandler implements
        AuthenticatorRequestHandler<WebAuthnAuthenticationValidationRequestModel>
{
    private final WebAuthnPluginConfiguration _configuration;
    private final ExceptionFactory _exceptionFactory;
    private final AccountManager _accountManager;
    private final SessionManager _sessionManager;

    public WebAuthnAuthenticationValidationRequestHandler(WebAuthnPluginConfiguration configuration)
    {
        _configuration = configuration;
        _accountManager = configuration.getAccountManager();
        _exceptionFactory = configuration.getExceptionFactory();
        _sessionManager = configuration.getSessionManager();
    }

    @Override
    public Optional<AuthenticationResult> get(WebAuthnAuthenticationValidationRequestModel request, Response response)
    {
        throw _exceptionFactory.methodNotAllowed();
    }

    @Override
    public Optional<AuthenticationResult> post(WebAuthnAuthenticationValidationRequestModel request, Response response)
    {
        Post model = request.getPostRequestModel();

        Optional<AuthenticationResult> authenticationResult = Optional.empty();

        WebAuthnAuthenticationSession webAuthnAuthenticationSession = WebAuthnAuthenticationSession.readFromSession(
                _sessionManager,
                _exceptionFactory);

        @Nullable
        AccountAttributes accountAttributes = _accountManager.getByUserName(
                webAuthnAuthenticationSession.getUsername());

        if (accountAttributes != null)
        {
            boolean validated = WebAuthnAuthenticatorLogic.validateAuthentication(_configuration, model,
                    accountAttributes);

            if (validated)
            {
                // Remove devices from account attributes before creating the authentication attributes so we avoid
                // exposing information about the devices
                @Nullable
                AccountAttributes accountAttributesWithoutDevices;
                List<Device> deviceList = accountAttributes.getDevices().toList();

                for (Device device : deviceList)
                {
                    accountAttributes = accountAttributes.removeDevice(device);
                }
                accountAttributesWithoutDevices = accountAttributes;

                if (accountAttributesWithoutDevices != null &&
                        accountAttributesWithoutDevices.getDevices().toList().isEmpty())
                {
                    AuthenticationAttributes authenticationAttributes = AuthenticationAttributes
                            .of(SubjectAttributes.of(accountAttributes.getUserName(), accountAttributesWithoutDevices),
                                    ContextAttributes.empty());

                    authenticationResult = Optional.of(new AuthenticationResult(authenticationAttributes));
                }
            }
        }

        WebAuthnAuthenticationSession.clear(_sessionManager);

        return authenticationResult;
    }

    @Override
    public WebAuthnAuthenticationValidationRequestModel preProcess(Request request, Response response)
    {
        String deviceSelectionUrl = _configuration.getAuthenticatorInformationProvider()
                .getFullyQualifiedAuthenticationUri().toString() + "/" + SELECT_DEVICE;

        response.setResponseModel(templateResponseModel(Collections.emptyMap(), "select-device/error"),
                FAILURE);
        response.putViewData("_deviceSelectionUrl", deviceSelectionUrl, FAILURE);

        return new WebAuthnAuthenticationValidationRequestModel(request);
    }
}
