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

import se.curity.identityserver.sdk.Nullable;
import se.curity.identityserver.sdk.config.Configuration;
import se.curity.identityserver.sdk.config.annotation.DefaultBoolean;
import se.curity.identityserver.sdk.config.annotation.DefaultEnum;
import se.curity.identityserver.sdk.config.annotation.Description;
import se.curity.identityserver.sdk.service.AccountManager;
import se.curity.identityserver.sdk.service.Bucket;
import se.curity.identityserver.sdk.service.ExceptionFactory;
import se.curity.identityserver.sdk.service.Json;
import se.curity.identityserver.sdk.service.SessionManager;
import se.curity.identityserver.sdk.service.UserPreferenceManager;
import se.curity.identityserver.sdk.service.authentication.AuthenticatorInformationProvider;

import java.util.List;
import java.util.Optional;

/**
 * WebAuthn Authenticator Configuration
 */
public interface WebAuthnPluginConfiguration extends Configuration
{
    AuthenticatorInformationProvider getAuthenticatorInformationProvider();

    UserPreferenceManager getUserPreferenceManager();

    SessionManager getSessionManager();

    ExceptionFactory getExceptionFactory();

    Json getJson();

    Bucket getBucket();

    @Description("The Account Manager where the users belong. Used to lookup the user and its associated devices")
    AccountManager getAccountManager();

    @DefaultBoolean(true)
    boolean getAllowedRegistrationDuringLogin();

    @Description("Set a device expiration in minutes from the time the device is activated, if not set devices never " +
            "expires. If this is set, it is not possible to override in the template. Only one device can be active " +
            "per account, registering a new device expires any previous ones. ")
    Optional<Integer> getDeviceExpiration();

    @Description("When active a login will be automatically performed after a successful registration.")
    @DefaultBoolean(false)
    boolean getAutoLoginEnabled();

    @DefaultBoolean(true)
    @Description("Check for potential cloned devices that could be using the same private key.")
    boolean getEnableValidationOfSignatureCounter();

    @DefaultBoolean(true)
    @Description("Require the device to perform Multi Factor Authentication to verify the identity of the user. When " +
            "enabled, the authentication will fail if the device fails to verify the user. The type of MFA used is " +
            "dependent on the device.")
    boolean getUserVerifiedByTheAuthenticatorDevice();

    @Description("The signature algorithms used by WebAuthn. This is in the form of a sequence and it is ordered " +
            "from most preferred to least preferred. The client makes a best-effort to create the most preferred " +
            "credential that it can.")
    List<Algorithm> getAlgorithms();

    /*
     * https://www.iana.org/assignments/cose/cose.xhtml#algorithms
     */
    enum Algorithm
    {
        RS256(-257, "RSA", "RSA", "SHA256withRSA"),
        RS384(-258, "RSA", "RSA", "SHA384withRSA"),
        RS512(-259, "RSA", "RSA", "SHA512withRSA"),
        PS256(-37, "RSA", "RSA", "SHA256withRSAandMGF1"),
        PS384(-38, "RSA", "RSA", "SHA384withRSAandMGF1"),
        PS512(-39, "RSA", "RSA", "SHA512withRSAandMGF1"),
        ES256(-7, "EC", "secp256r1", "EC", "SHA256withECDSA"),
        ES384(-35, "EC", "secp384r1", "EC", "SHA384withECDSA"),
        ES512(-36, "EC", "secp512r1", "EC", "SHA512withECDSA");

        private final int _algorithmCode;
        private final String _algorithmParametersAlgorithm;
        @Nullable
        private final String _ecGenParameterSpecStdName;
        private final String _keyFactoryAlgorithm;
        private final String _signatureAlgorithm;

        Algorithm(int coseNumber, String algorithmParametersAlgorithm, String ecGenParameterSpecStdName,
                  String keyFactoryAlgorithm, String signatureAlgorithm)
        {
            _algorithmCode = coseNumber;
            _algorithmParametersAlgorithm = algorithmParametersAlgorithm;
            _ecGenParameterSpecStdName = ecGenParameterSpecStdName;
            _keyFactoryAlgorithm = keyFactoryAlgorithm;
            _signatureAlgorithm = signatureAlgorithm;
        }

        Algorithm(int coseNumber, String algorithmParametersAlgorithm, String keyFactoryAlgorithm, String signatureAlgorithm)
        {
            _algorithmCode = coseNumber;
            _algorithmParametersAlgorithm = algorithmParametersAlgorithm;
            _ecGenParameterSpecStdName = null;
            _keyFactoryAlgorithm = keyFactoryAlgorithm;
            _signatureAlgorithm = signatureAlgorithm;
        }

        public static Algorithm getAlgorithmNameByCode(int code)
        {
            for (Algorithm alg : Algorithm.values())
            {
                if (code == alg._algorithmCode)
                {
                    return alg;
                }
            }

            throw new RuntimeException("Error, provided algorithm is not supported.");
        }

        public int getAlgorithmCode()
        {
            return _algorithmCode;
        }

        public String getAlgorithmParametersAlgorithm()
        {
            return _algorithmParametersAlgorithm;
        }

        @Nullable
        public String getEcGenParameterSpecStdName()
        {
            return _ecGenParameterSpecStdName;
        }

        public String getKeyFactoryAlgorithm()
        {
            return _keyFactoryAlgorithm;
        }

        public String getSignatureAlgorithm()
        {
            return _signatureAlgorithm;
        }
    }

    @DefaultEnum("any")
    AuthenticatorAttachment getAuthenticatorAttachment();

    enum AuthenticatorAttachment
    {
        platform("platform"),
        cross_platform("cross-platform"),
        any(null);

        @Nullable
        private final String _authenticatorAttachment;

        AuthenticatorAttachment(@Nullable String authenticatorAttachment)
        {
            _authenticatorAttachment = authenticatorAttachment;
        }

        @Nullable
        public String get()
        {
            return _authenticatorAttachment;
        }
    }

    String getOrganizationName();

    @Description("This option allows servers to indicate how important the attestation data is to this registration " +
            "event.")
    @DefaultEnum("none")
    Attestation getAttestation();

    enum Attestation
    {
        none,
        direct,
        indirect
    }

    @Description("Resident key means that the private key used during the authentication is kept in the device. The " +
            "discouraged option means tha the private key could be stored in the server and sent back encrypted to " +
            "the device when it would need to use it for authentication.")
    @DefaultEnum("preferred")
    ResidentKeyRequirement getResidentKeyRequirement();

    enum ResidentKeyRequirement
    {
        discouraged,
        preferred,
        required
    }
}
