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
import io.curity.identityserver.plugin.webauthn.authenticate.WebAuthnSelectDeviceRequestModel.Post;
import org.apache.commons.lang3.RandomUtils;
import se.curity.identityserver.sdk.attribute.Attribute;
import se.curity.identityserver.sdk.attribute.scim.v2.extensions.Device;
import se.curity.identityserver.sdk.authentication.AuthenticationResult;
import se.curity.identityserver.sdk.authentication.AuthenticatorRequestHandler;
import se.curity.identityserver.sdk.service.AccountManager;
import se.curity.identityserver.sdk.service.ExceptionFactory;
import se.curity.identityserver.sdk.service.SessionManager;
import se.curity.identityserver.sdk.web.Request;
import se.curity.identityserver.sdk.web.Response;

import java.time.Instant;
import java.util.Base64;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

import static io.curity.identityserver.plugin.webauthn.WebAuthnAuthenticatorLogic.CREDENTIAL_ID_ATTRIBUTE;
import static io.curity.identityserver.plugin.webauthn.WebAuthnPluginDescriptor.SELECT_DEVICE;
import static io.curity.identityserver.plugin.webauthn.WebAuthnPluginDescriptor.VALIDATION;
import static se.curity.identityserver.sdk.errors.ErrorCode.MISSING_PARAMETERS;
import static se.curity.identityserver.sdk.http.HttpStatus.OK;
import static se.curity.identityserver.sdk.web.Response.ResponseModelScope.ANY;
import static se.curity.identityserver.sdk.web.ResponseModel.templateResponseModel;

public final class WebAuthnSelectDeviceRequestHandler implements
        AuthenticatorRequestHandler<WebAuthnSelectDeviceRequestModel>
{
    private final WebAuthnPluginConfiguration _configuration;
    private final SessionManager _sessionManager;
    private final AccountManager _accountManager;
    private final ExceptionFactory _exceptionFactory;
    private final String _usernameInAuthSession;

    public WebAuthnSelectDeviceRequestHandler(WebAuthnPluginConfiguration configuration)
    {
        _configuration = configuration;
        _accountManager = configuration.getAccountManager();
        _sessionManager = configuration.getSessionManager();
        _exceptionFactory = configuration.getExceptionFactory();

        WebAuthnAuthenticationSession webAuthnAuthenticationSession = WebAuthnAuthenticationSession.readFromSession(
                _sessionManager,
                _exceptionFactory);

        _usernameInAuthSession = webAuthnAuthenticationSession.getUsername();
    }

    @Override
    public WebAuthnSelectDeviceRequestModel preProcess(Request request, Response response)
    {
        response.setResponseModel(templateResponseModel(Collections.emptyMap(),
                "select-device/device-selector"), ANY);

        response.putViewData("_allowRegistrationDuringLogin",
                _configuration.getAllowedRegistrationDuringLogin(), ANY);
        response.putViewData("_registrationEndpoint",
                _configuration.getAuthenticatorInformationProvider().getFullyQualifiedRegistrationUri(), ANY);
        response.putViewData("_validationEndpoint", _configuration.getAuthenticatorInformationProvider()
                .getFullyQualifiedAuthenticationUri() + "/" + VALIDATION, ANY);
        response.putViewData("_selectDeviceEndpoint", _configuration.getAuthenticatorInformationProvider()
                .getFullyQualifiedAuthenticationUri() + "/" + SELECT_DEVICE, ANY);

        return new WebAuthnSelectDeviceRequestModel(request, _usernameInAuthSession);
    }

    @Override
    public Optional<AuthenticationResult> get(WebAuthnSelectDeviceRequestModel request, Response response)
    {
        return handle(getDevicesForUser(_usernameInAuthSession), response);
    }

    @Override
    public Optional<AuthenticationResult> post(WebAuthnSelectDeviceRequestModel request, Response response)
    {
        Post model = request.getPostRequestModel();
        List<Device> devicesByUserName = getDevicesForUser(_usernameInAuthSession);

        Optional<Device> maybeSelectedDevice = devicesByUserName.stream().filter(device ->
                model.getDeviceId().equals(device.getDeviceId())).findFirst();

        if (!maybeSelectedDevice.isPresent())
        {
            throw _exceptionFactory.badRequestException(MISSING_PARAMETERS, "error.device.invalid");
        }

        return showLoginTemplate(maybeSelectedDevice.get(), response);
    }

    private Optional<AuthenticationResult> handle(List<Device> deviceList, Response response)
    {
        if (deviceList.size() == 1)
        {
            // found one device, use that to authenticate the user
            return showLoginTemplate(deviceList.get(0), response);
        }
        else
        {
            // found none or multiple devices, show selection screen
            response.putViewData("_devices", deviceList, ANY);
        }

        return Optional.empty();
    }

    private Optional<AuthenticationResult> showLoginTemplate(Device device, Response response)
    {
        response.setResponseModel(templateResponseModel(Collections.emptyMap(), "select-device/index"), OK);
        response.putViewData("_credentialId", device.get(CREDENTIAL_ID_ATTRIBUTE).getValue(), ANY);

        String challenge = new String(Base64.getEncoder().encode(RandomUtils.nextBytes(32)));
        _sessionManager.put(Attribute.of("authChallenge", challenge));

        response.putViewData("_userVerification", _configuration.getResidentKeyRequirement(), ANY);
        response.putViewData("_challenge", challenge, ANY);
        response.putViewData("_timeout", 60000, ANY);

        return Optional.empty();
    }

    List<Device> getDevicesForUser(String username)
    {
        Collection<Device> allDevices = _accountManager.getDevicesByUserName(username);
        Instant now = Instant.now();

        return allDevices.stream()
                .filter(device -> device.getExpiresAt() == null || now.isBefore(device.getExpiresAt()))
                .collect(Collectors.toList());
    }
}
