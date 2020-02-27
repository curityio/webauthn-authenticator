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

package io.curity.identityserver.plugin.webauthn.register;

import com.google.common.collect.ImmutableMap;
import io.curity.identityserver.plugin.webauthn.WebAuthnAuthenticatorLogic;
import io.curity.identityserver.plugin.webauthn.WebAuthnPluginConfiguration;
import org.apache.commons.lang3.RandomUtils;
import se.curity.identityserver.sdk.Nullable;
import se.curity.identityserver.sdk.attribute.AccountAttributes;
import se.curity.identityserver.sdk.attribute.Attribute;
import se.curity.identityserver.sdk.attribute.Attributes;
import se.curity.identityserver.sdk.attribute.scim.v2.extensions.DeviceAttributes;
import se.curity.identityserver.sdk.authentication.AuthenticatedState;
import se.curity.identityserver.sdk.authentication.RegistrationRequestHandler;
import se.curity.identityserver.sdk.authentication.RegistrationResult;
import se.curity.identityserver.sdk.errors.ErrorCode;
import se.curity.identityserver.sdk.service.AccountManager;
import se.curity.identityserver.sdk.service.AutoLoginManager;
import se.curity.identityserver.sdk.service.ExceptionFactory;
import se.curity.identityserver.sdk.service.SessionManager;
import se.curity.identityserver.sdk.web.Request;
import se.curity.identityserver.sdk.web.Response;

import java.time.Instant;
import java.util.Base64;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

import static io.curity.identityserver.plugin.webauthn.WebAuthnAuthenticatorLogic.CREDENTIAL_ID_ATTRIBUTE;
import static io.curity.identityserver.plugin.webauthn.WebAuthnAuthenticatorLogic.CREDENTIAL_PUBLIC_KEY_ATTRIBUTE;
import static io.curity.identityserver.plugin.webauthn.WebAuthnAuthenticatorLogic.RAW_ID_ATTRIBUTE;
import static io.curity.identityserver.plugin.webauthn.WebAuthnAuthenticatorLogic.STORED_SIGN_COUNT_ATTRIBUTE;
import static java.time.temporal.ChronoUnit.MINUTES;
import static java.util.Collections.emptyMap;
import static se.curity.identityserver.sdk.attribute.scim.v2.extensions.DeviceAttributes.ALIAS;
import static se.curity.identityserver.sdk.attribute.scim.v2.extensions.DeviceAttributes.DEVICE_ID;
import static se.curity.identityserver.sdk.attribute.scim.v2.extensions.DeviceAttributes.EXPIRES_AT;
import static se.curity.identityserver.sdk.web.Response.ResponseModelScope.ANY;
import static se.curity.identityserver.sdk.web.Response.ResponseModelScope.FAILURE;
import static se.curity.identityserver.sdk.web.Response.ResponseModelScope.NOT_FAILURE;
import static se.curity.identityserver.sdk.web.ResponseModel.templateResponseModel;

public class WebAuthnRegistrationRequestHandler implements RegistrationRequestHandler<WebAuthnRegistrationRequestModel>
{
    private static final String SESSION_CHALLENGE = "webauthn:challenge";
    public static final String BUCKET_WEBAUTHN_STORED_SIGNED_COUNT = "bucket_webauthn_stored_signed_count";
    private final WebAuthnPluginConfiguration _configuration;
    private final AccountManager _accountManager;
    private final SessionManager _sessionManager;
    private final AutoLoginManager _autoLoginManager;
    private final AuthenticatedState _authenticatedState;
    private final ExceptionFactory _exceptionFactory;
    private static String _registrationChallenge;

    public WebAuthnRegistrationRequestHandler(WebAuthnPluginConfiguration configuration,
                                              AuthenticatedState authenticatedState,
                                              AutoLoginManager autoLoginManager)
    {
        _configuration = configuration;
        _accountManager = configuration.getAccountManager();
        _sessionManager = configuration.getSessionManager();
        _autoLoginManager = autoLoginManager;
        _authenticatedState = authenticatedState;
        _exceptionFactory = configuration.getExceptionFactory();
    }

    @Override
    public WebAuthnRegistrationRequestModel preProcess(Request request, Response response)
    {
        if (!_accountManager.supportsRegistration())
        {
            throw _exceptionFactory.internalServerException(ErrorCode.CONFIGURATION_ERROR,
                    "The configured Account Manager does not support registration, check the data source " +
                            "configuration of the account manager");
        }

        if (!_authenticatedState.isAuthenticated())
        {
            throw _exceptionFactory.unauthorizedException(ErrorCode.ACCESS_DENIED, "Not Authorized");
        }

        if (request.isPostRequest())
        {
            response.setResponseModel(templateResponseModel(emptyMap(), "register/error"),
                    FAILURE);

            response.setResponseModel(templateResponseModel(emptyMap(), "register/done"),
                    NOT_FAILURE);
        }
        else if (request.isGetRequest())
        {
            response.setResponseModel(templateResponseModel(emptyMap(), "register/get"),
                    ANY);
        }

        return new WebAuthnRegistrationRequestModel(request);
    }

    @Override
    public Optional<RegistrationResult> get(WebAuthnRegistrationRequestModel requestModel, Response response)
    {
        _registrationChallenge = new String(Base64.getEncoder().encode(RandomUtils.nextBytes(32)));
        _sessionManager.put(Attribute.of(SESSION_CHALLENGE, _registrationChallenge));
        String username = _authenticatedState.getUsername();
        @Nullable
        AccountAttributes account = _accountManager.getByUserName(username);

        if (account == null)
        {
            throw _exceptionFactory.internalServerException(ErrorCode.ACCESS_DENIED,
                    "There is no account for the provided username in the configured Account Manager");
        }

        response.putViewData("_registrationEndpoint", _configuration.getAuthenticatorInformationProvider()
                .getFullyQualifiedRegistrationUri(), ANY);
        response.putViewData("_challenge", _registrationChallenge, ANY);
        response.putViewData("_rpName", _configuration.getOrganisationName(), ANY);
        response.putViewData("_userId", account.getId(), ANY);
        response.putViewData("_userName", username, ANY);
        response.putViewData("_userDisplayName", account.getDisplayName() == null ?
                username : account.getDisplayName(), ANY);
        response.putViewData("_pubKeyCredParamsAlg", WebAuthnAuthenticatorLogic.getSupportedAlgorithms(
                _configuration.getJson(), _configuration.getAlgorithms()), ANY);
        response.putViewData("_authenticatorAttachment", _configuration.getAuthenticatorAttachment().get(), ANY);
        response.putViewData("_timeout", TimeUnit.SECONDS.toSeconds(60), ANY);
        response.putViewData("_attestation", _configuration.getAttestation(), ANY);
        response.putViewData("_residentKeyRequirement", _configuration.getResidentKeyRequirement(), ANY);

        return Optional.empty();
    }

    @Override
    public Optional<RegistrationResult> post(WebAuthnRegistrationRequestModel request, Response response)
    {
        WebAuthnRegistrationRequestModel.Post model = request.getPostRequestModel();

        Map<String, String> registrationResult = WebAuthnAuthenticatorLogic.validateRegistration(_configuration,
                request.getPostRequestModel(), _registrationChallenge);

        String username = _authenticatedState.getUsername();
        String deviceId = UUID.randomUUID().toString();

        @Nullable
        Instant deviceExpiresAt = null;

        if (_configuration.getDeviceExpiration().isPresent())
        {
            deviceExpiresAt = Instant.now().plus(_configuration.getDeviceExpiration().get(), MINUTES);
        }

        ImmutableMap.Builder<String, Object> deviceAttributes = ImmutableMap.<String, Object>builder()
                .put(DEVICE_ID, deviceId)
                .put(ALIAS, model.getAlias())
                .put(RAW_ID_ATTRIBUTE, model.getRawId())
                .put(CREDENTIAL_ID_ATTRIBUTE, registrationResult.get(CREDENTIAL_ID_ATTRIBUTE))
                .put(CREDENTIAL_PUBLIC_KEY_ATTRIBUTE, registrationResult.get(CREDENTIAL_PUBLIC_KEY_ATTRIBUTE));

        if (deviceExpiresAt != null)
        {
            deviceAttributes.put(EXPIRES_AT, deviceExpiresAt.toString());
        }

        _accountManager.addDeviceForUser(username,
                DeviceAttributes.of(Attributes.fromMap(deviceAttributes.build())));

        _configuration.getBucket().storeAttributes(deviceId, BUCKET_WEBAUTHN_STORED_SIGNED_COUNT,
                ImmutableMap.of(STORED_SIGN_COUNT_ATTRIBUTE, "0"));

        setupAutoLogin(response, _accountManager.getByUserName(username));

        return Optional.empty();
    }

    private void setupAutoLogin(Response response, AccountAttributes account)
    {
        if (_configuration.getAutoLoginEnabled())
        {
            _autoLoginManager.prepareAutoLoginNonce(account)
                    .ifPresent(confirmData -> AutoLoginManager.addToResponse(response, confirmData));
        }
    }
}
