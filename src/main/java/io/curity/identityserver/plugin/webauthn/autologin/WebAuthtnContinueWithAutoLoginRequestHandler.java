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

package io.curity.identityserver.plugin.webauthn.autologin;

import io.curity.identityserver.plugin.webauthn.WebAuthnPluginConfiguration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import se.curity.identityserver.sdk.Nullable;
import se.curity.identityserver.sdk.authentication.AnonymousRequestHandler;
import se.curity.identityserver.sdk.service.AutoLoginManager;
import se.curity.identityserver.sdk.service.ExceptionFactory;
import se.curity.identityserver.sdk.web.Request;
import se.curity.identityserver.sdk.web.Response;

import java.net.URI;

public class WebAuthtnContinueWithAutoLoginRequestHandler implements
        AnonymousRequestHandler<ContinueWithAutoLoginRequestModel>
{
    private static final Logger _logger = LoggerFactory.getLogger(WebAuthtnContinueWithAutoLoginRequestHandler.class);
    private final AutoLoginManager _autoLoginManager;
    private final WebAuthnPluginConfiguration _configuration;
    private final ExceptionFactory _exceptionFactory;

    public WebAuthtnContinueWithAutoLoginRequestHandler(AutoLoginManager autoLoginManager,
                                                        WebAuthnPluginConfiguration configuration)
    {
        _autoLoginManager = autoLoginManager;
        _configuration = configuration;
        _exceptionFactory = configuration.getExceptionFactory();
    }

    @Override
    public ContinueWithAutoLoginRequestModel preProcess(Request request, Response response)
    {
        return new ContinueWithAutoLoginRequestModel(request);
    }

    @Override
    public Void get(ContinueWithAutoLoginRequestModel requestModel, Response response)
    {
        throw _exceptionFactory.methodNotAllowed();
    }

    @Override
    public Void post(ContinueWithAutoLoginRequestModel requestModel, Response response)
    {
        @Nullable
        String nonceSessionKey = requestModel.getNonceSessionKey();

        if (_configuration.getAutoLoginEnabled() && nonceSessionKey != null)
        {
            _logger.debug("auto-login nonce enabled");
            _autoLoginManager.enableAutoLoginNonce(nonceSessionKey);
        }

        @Nullable
        URI authnUri = _configuration.getAuthenticatorInformationProvider().getFullyQualifiedAuthenticationUri();

        if (authnUri == null)
        {
            String msg = "FullyQualifiedAuthenticationUri is null, however it is need to continue processing";
            _logger.error(msg);

            throw new RuntimeException(msg);
        }
        String authnUriString = authnUri.toString();

        throw _exceptionFactory.redirectException(authnUriString);
    }
}
