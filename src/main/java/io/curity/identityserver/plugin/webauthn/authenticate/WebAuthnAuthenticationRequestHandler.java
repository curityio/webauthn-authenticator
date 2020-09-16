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
import io.curity.identityserver.plugin.webauthn.WebAuthnPluginConfiguration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import se.curity.identityserver.sdk.Nullable;
import se.curity.identityserver.sdk.attribute.AccountAttributes;
import se.curity.identityserver.sdk.authentication.AuthenticatedState;
import se.curity.identityserver.sdk.authentication.AuthenticationResult;
import se.curity.identityserver.sdk.authentication.AuthenticatorRequestHandler;
import se.curity.identityserver.sdk.http.HttpStatus;
import se.curity.identityserver.sdk.service.AccountManager;
import se.curity.identityserver.sdk.service.AutoLoginManager;
import se.curity.identityserver.sdk.service.ExceptionFactory;
import se.curity.identityserver.sdk.service.SessionManager;
import se.curity.identityserver.sdk.service.UserPreferenceManager;
import se.curity.identityserver.sdk.web.Request;
import se.curity.identityserver.sdk.web.Response;

import java.util.Collections;
import java.util.Optional;

import static io.curity.identityserver.plugin.webauthn.WebAuthnPluginDescriptor.SELECT_DEVICE;
import static se.curity.identityserver.sdk.errors.ErrorCode.NO_ACCOUNT_TO_SELECT;
import static se.curity.identityserver.sdk.http.HttpStatus.OK;
import static se.curity.identityserver.sdk.web.Response.ResponseModelScope.NOT_FAILURE;
import static se.curity.identityserver.sdk.web.ResponseModel.templateResponseModel;

public final class WebAuthnAuthenticationRequestHandler implements
        AuthenticatorRequestHandler<WebAuthnAuthenticationRequestModel>
{
    private static final Logger _logger = LoggerFactory.getLogger(WebAuthnAuthenticationRequestHandler.class);
    private final WebAuthnPluginConfiguration _configuration;
    private final AccountManager _accountManager;
    private final UserPreferenceManager _userPreferenceManager;
    private final AutoLoginManager _autoLoginManager;
    private final AuthenticatedState _authenticatedState;
    private final ExceptionFactory _exceptionFactory;
    private final SessionManager _sessionManager;

    public WebAuthnAuthenticationRequestHandler(WebAuthnPluginConfiguration configuration,
                                                AuthenticatedState authenticatedState,
                                                AutoLoginManager autoLoginManager)
    {
        _configuration = configuration;
        _accountManager = configuration.getAccountManager();
        _userPreferenceManager = configuration.getUserPreferenceManager();
        _autoLoginManager = autoLoginManager;
        _authenticatedState = authenticatedState;
        _exceptionFactory = configuration.getExceptionFactory();
        _sessionManager = configuration.getSessionManager();
    }

    @Override
    public WebAuthnAuthenticationRequestModel preProcess(Request request, Response response)
    {
        response.setResponseModel(templateResponseModel(Collections.emptyMap(),
                "enter-username/index"), HttpStatus.BAD_REQUEST);
        response.putViewData("_registrationEndpoint",
                _configuration.getAuthenticatorInformationProvider().getFullyQualifiedRegistrationUri(),
                Response.ResponseModelScope.ANY);

        return new WebAuthnAuthenticationRequestModel(request);
    }

    @Override
    public Optional<AuthenticationResult> get(WebAuthnAuthenticationRequestModel requestModel, Response response)
    {
        if (_configuration.getAutoLoginEnabled())
        {
            Optional<AuthenticationResult> maybeResult = _autoLoginManager.getAutoLoginFromCurrentSession();
            if (maybeResult.isPresent())
            {
                return maybeResult;
            }
        }

        if (!_authenticatedState.isAuthenticated())
        {
            response.putViewData("_username", _configuration.getUserPreferenceManager().getUsername(),
                    NOT_FAILURE);
            response.setResponseModel(templateResponseModel(Collections.emptyMap(), "enter-username/index"),
                    OK);

            return Optional.empty();
        }

        checkAndStoreUsername(_authenticatedState.getUsername());

        return redirectToDeviceSelection();
    }

    @Override
    public Optional<AuthenticationResult> post(WebAuthnAuthenticationRequestModel requestModel, Response response)
    {
        WebAuthnAuthenticationRequestModel.Post model = requestModel.getPostRequestModel();
        checkAndStoreUsername(model.getUsername());

        return redirectToDeviceSelection();
    }

    private void checkAndStoreUsername(String username)
    {
        @Nullable
        AccountAttributes account = _accountManager.getByUserName(username);

        if (account != null)
        {
            WebAuthnAuthenticationSession.createAndSave(username, _sessionManager);
            _userPreferenceManager.saveUsername(username);
        }
        else
        {
            throw _exceptionFactory.badRequestException(NO_ACCOUNT_TO_SELECT, "error.username.invalid");
        }
    }

    private Optional<AuthenticationResult> redirectToDeviceSelection()
    {
        String url = _configuration.getAuthenticatorInformationProvider().getFullyQualifiedAuthenticationUri()
                .toString() + "/" + SELECT_DEVICE;

        _logger.trace("redirecting to {}", url);

        throw _exceptionFactory.redirectException(url);
    }
}
