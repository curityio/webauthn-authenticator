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

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.cbor.CBORFactory;
import com.google.common.collect.ImmutableMap;
import io.curity.identityserver.plugin.webauthn.WebAuthnPluginConfiguration.Algorithm;
import io.curity.identityserver.plugin.webauthn.authenticate.WebAuthnAuthenticationValidationRequestModel;
import io.curity.identityserver.plugin.webauthn.register.WebAuthnRegistrationRequestModel;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import se.curity.identityserver.sdk.Nullable;
import se.curity.identityserver.sdk.attribute.AccountAttributes;
import se.curity.identityserver.sdk.attribute.scim.v2.extensions.Device;
import se.curity.identityserver.sdk.attribute.scim.v2.extensions.DeviceAttributes;
import se.curity.identityserver.sdk.service.AccountManager;
import se.curity.identityserver.sdk.service.Bucket;
import se.curity.identityserver.sdk.service.ExceptionFactory;
import se.curity.identityserver.sdk.service.Json;
import se.curity.identityserver.sdk.service.SessionManager;
import se.curity.identityserver.sdk.service.UserPreferenceManager;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.math.BigInteger;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static io.curity.identityserver.plugin.webauthn.WebAuthnPluginConfiguration.Attestation;
import static io.curity.identityserver.plugin.webauthn.WebAuthnPluginConfiguration.ResidentKeyRequirement;
import static io.curity.identityserver.plugin.webauthn.register.WebAuthnRegistrationRequestHandler.BUCKET_WEBAUTHN_STORED_SIGNED_COUNT;
import static se.curity.identityserver.sdk.errors.ErrorCode.CONFIGURATION_ERROR;
import static se.curity.identityserver.sdk.errors.ErrorCode.GENERIC_ERROR;

public class WebAuthnAuthenticatorLogic
{
    private static final Logger _logger = LoggerFactory.getLogger(WebAuthnAuthenticatorLogic.class);
    private static final String WEBAUTHN_CREATE = "webauthn.create";
    private static final String WEBAUTHN_GET = "webauthn.get";
    public static final String RAW_ID_ATTRIBUTE = "rawId";
    public static final String CREDENTIAL_PUBLIC_KEY_ATTRIBUTE = "credentialPublicKey";
    public static final String CREDENTIAL_ID_ATTRIBUTE = "credentialId";
    public static final String STORED_SIGN_COUNT_ATTRIBUTE = "storedSignCount";

    public static String getSupportedAlgorithms(Json json, List<Algorithm> algorithmList)
    {
        return json.toJson(algorithmList.stream().map(value ->
                ImmutableMap.of("alg", value.getAlgorithmCode(), "type", "public-key"))
                .collect(Collectors.toList()));
    }

    public static boolean validateAuthentication(WebAuthnPluginConfiguration configuration,
                                                 WebAuthnAuthenticationValidationRequestModel.Post request,
                                                 AccountAttributes accountAttributes)
    {
        ExceptionFactory exceptionFactory = configuration.getExceptionFactory();
        AccountManager accountManager = configuration.getAccountManager();
        SessionManager sessionManager = configuration.getSessionManager();
        UserPreferenceManager userPreferenceManager = configuration.getUserPreferenceManager();
        Json json = configuration.getJson();
        Bucket bucket = configuration.getBucket();

        // https://www.w3.org/TR/webauthn-2/#sctn-verifying-assertion

        // Step 5: If options.allowCredentials is not empty, verify that credential.id identifies one of the public key
        // credentials listed in options.allowCredentials.
        String rawId = request.getRawId();

        Collection<Device> devices = accountAttributes.getDevices().toList();
        Instant now = Instant.now();
        List<Device> deviceList = devices.stream()
                .filter(device -> device.get(CREDENTIAL_ID_ATTRIBUTE).getValue().equals(request.getRawId()))
                .filter(device -> device.getExpiresAt() == null || now.isBefore(device.getExpiresAt()))
                .collect(Collectors.toList());

        if (deviceList.isEmpty())
        {
            _logger.debug("No devices were found with credentialId: {}", rawId);

            throw exceptionFactory.badRequestException(GENERIC_ERROR, "error.authentication-failed");
        }

        // Step 6: Identify the user being authenticated and verify that this user is the owner of the public key
        // credential source credentialSource identified by credential.id
        String userHandle = request.getUserHandle();
        String registeredUserId = Base64.getEncoder().encodeToString(accountManager.getByUserName(
                userPreferenceManager.getUsername()).getId().getBytes());

        if (!userHandle.isEmpty() && !userHandle.equals(registeredUserId))
        {
            _logger.debug("Failed to validate userHandle against the registered user id.");

            throw exceptionFactory.badRequestException(GENERIC_ERROR, "error.authentication-failed");
        }

        // Step 7: Using credential.id (or credential.rawId, if base64url encoding is inappropriate for your use case),
        // look up the corresponding credential public key and let credentialPublicKey be that credential public key.
        DeviceAttributes deviceAttributes = deviceList.get(0).getAttributes();
        CredentialPublicKey credentialPublicKey;

        try
        {
            ObjectMapper mapper = new ObjectMapper()
                    .configure(JsonParser.Feature.ALLOW_UNQUOTED_FIELD_NAMES, true);
            credentialPublicKey = new CredentialPublicKey(
                    mapper.readTree(deviceAttributes.get(CREDENTIAL_PUBLIC_KEY_ATTRIBUTE).getValue().toString()),
                    exceptionFactory.badRequestException(GENERIC_ERROR, "error.authentication-failed"));
        }
        catch (IOException e)
        {
            throw new UncheckedIOException("Error when parsing credentialPublicKey from data-source.", e);
        }

        // Step 8: Let cData, authData and sig denote the value of response’s clientDataJSON, authenticatorData, and
        // signature respectively
        byte[] cData = Base64.getDecoder().decode(request.getClientDataJSON());
        byte[] authData = Base64.getDecoder().decode(request.getAuthenticatorData());
        byte[] sig = Base64.getDecoder().decode(request.getSignature());

        // Step 9: Let JSONtext be the result of running UTF-8 decode on the value of cData.
        // Step 10: Let C, the client data claimed as used for the signature, be the result of running an
        // implementation-specific JSON parser on JSONtext.
        Map<String, Object> cDataAsMap = json.fromJson(new String(cData, StandardCharsets.UTF_8));

        // Step 11: Verify that the value of C.type is the string webauthn.get.
        String clientDataType = cDataAsMap.get("type").toString();

        if (!clientDataType.equals(WEBAUTHN_GET))
        {
            _logger.debug("Failed to validate clientData.type, value: {}, expected value: {}",
                    clientDataType, WEBAUTHN_GET);

            throw exceptionFactory.badRequestException(GENERIC_ERROR, "error.authentication-failed");
        }

        // Step 12: Verify that the value of C.challenge equals the base64url encoding of options.challenge.
        String clientDataChallenge = new String(Base64.getDecoder().decode(cDataAsMap.get("challenge").toString()),
                StandardCharsets.UTF_8);
        String authChallenge = sessionManager.get("authChallenge").getValue().toString();

        if (!clientDataChallenge.equals(authChallenge))
        {
            _logger.debug("Failed to validate clientData.challenge, value: {}, expected value: {}",
                    clientDataChallenge, authChallenge);

            throw exceptionFactory.badRequestException(GENERIC_ERROR, "error.authentication-failed");
        }

        // Step 13: Verify that the value of C.origin matches the Relying Party's origin.

        String relyingPartyOrigin;

        try
        {
            relyingPartyOrigin = new URI(request.getRequestUrl()).getHost();
            String clientDataOrigin = new URI(cDataAsMap.get("origin").toString()).getHost();

            if (!clientDataOrigin.equals(relyingPartyOrigin))
            {
                _logger.debug("Failed to validate clientData.origin, value: {}, expected value: {}",
                        clientDataChallenge, relyingPartyOrigin);

                throw exceptionFactory.badRequestException(GENERIC_ERROR, "error.authentication-failed");
            }
        }
        catch (URISyntaxException e)
        {
            _logger.debug("Failed to validate clientData.origin: {}", e.getMessage());

            throw exceptionFactory.badRequestException(GENERIC_ERROR, "error.authentication-failed");
        }

        // Step 14: Verify that the value of C.tokenBinding.status matches the state of Token Binding for the TLS
        // connection over which the attestation was obtained. If Token Binding was used on that TLS connection, also
        // verify that C.tokenBinding.id matches the base64url encoding of the Token Binding ID for the connection.

        // TODO implement token binding

        // Step 15: Verify that the rpIdHash in authData is the SHA-256 hash of the RP ID expected by the Relying Party.
        byte[] authDataRpIdHash = Arrays.copyOfRange(authData, 0, 32);

        byte[] expectedRpIdHash = getSHA256Hash(relyingPartyOrigin.getBytes());

        if (!Arrays.equals(authDataRpIdHash, expectedRpIdHash))
        {
            if (_logger.isDebugEnabled())
            {
                _logger.debug("Failed to validate rpIdHash from authData, value: {}, expected value: {}",
                        new String(authDataRpIdHash, StandardCharsets.UTF_8),
                        new String(expectedRpIdHash, StandardCharsets.UTF_8));
            }

            throw exceptionFactory.badRequestException(GENERIC_ERROR, "error.authentication-failed");
        }

        // Step 16: Verify that the User Present bit of the flags in authData is set.
        byte userPresentFlag = Arrays.copyOfRange(authData, 31, 32)[0];
        boolean userPresentBit = isNthBitSet(userPresentFlag, 0);

        if (!userPresentBit)
        {
            _logger.debug("Failed to validate that the User Present bit in authData is set");

            throw exceptionFactory.badRequestException(GENERIC_ERROR, "error.authentication-failed");
        }

        // Step 17: If user verification is required for this assertion, verify that the User Verified bit of the flags
        // in authData is set.
        byte byteToCheck = Arrays.copyOfRange(authData, 31, 32)[0];

        if (configuration.getResidentKeyRequirement().equals(
                ResidentKeyRequirement.required) && isNthBitSet(byteToCheck, 3))
        {
            _logger.debug("Failed to validate that the User Verified bit in authData is set");

            throw exceptionFactory.badRequestException(GENERIC_ERROR, "error.authentication-failed");
        }

        // Step 19: Let hash be the result of computing a hash over the cData using SHA-256.
        byte[] cDataHash = getSHA256Hash(cData);

        // Step 20: Using credentialPublicKey, verify that sig is a valid signature over the binary concatenation of
        // authData and hash
        byte[] authDataAndHash = new byte[authData.length + cDataHash.length];
        System.arraycopy(authData, 0, authDataAndHash, 0, authData.length);
        System.arraycopy(cDataHash, 0, authDataAndHash, authData.length, cDataHash.length);

        byte[] xCoordinate = Base64.getDecoder().decode(credentialPublicKey.getXCoordinate());
        byte[] yCoordinate = Base64.getDecoder().decode(credentialPublicKey.getYCoordinate());

        Algorithm algorithm = Algorithm.getAlgorithmNameByCode(credentialPublicKey.getAlg());

        if (!algorithm.equals(Algorithm.ES256))
        {
            _logger.warn("Error, algorithm {} is not supported", algorithm.name());

            throw exceptionFactory.badRequestException(CONFIGURATION_ERROR, "error.authentication-failed");
        }

        String algorithmParametersAlgorithm = algorithm.getAlgorithmParametersAlgorithm();
        String ecGenParameterSpecStdName = algorithm.getEcGenParameterSpecStdName();
        String keyFactoryAlgorithm = algorithm.getKeyFactoryAlgorithm();
        String signatureAlgorithm = algorithm.getSignatureAlgorithm();

        AlgorithmParameters algorithmParameters;
        ECParameterSpec ecParameterSpec;

        try
        {
            algorithmParameters = AlgorithmParameters.getInstance(algorithmParametersAlgorithm);
            algorithmParameters.init(new ECGenParameterSpec(ecGenParameterSpecStdName));
            ecParameterSpec = algorithmParameters.getParameterSpec(ECParameterSpec.class);
            ECPoint ecPoint = new ECPoint(new BigInteger(1, xCoordinate), new BigInteger(1, yCoordinate));
            ECPublicKeySpec ecPublicKeySpec = new ECPublicKeySpec(ecPoint, ecParameterSpec);
            PublicKey publicKey = KeyFactory.getInstance(keyFactoryAlgorithm).generatePublic(ecPublicKeySpec);
            Signature signature = Signature.getInstance(signatureAlgorithm);
            signature.initVerify(publicKey);
            signature.update(authDataAndHash);
            boolean verifiedSignature = signature.verify(sig);

            if (!verifiedSignature)
            {
                _logger.debug("Failed to validate the signature of the response.");

                throw exceptionFactory.badRequestException(GENERIC_ERROR, "error.authentication-failed");
            }
        }
        catch (NoSuchAlgorithmException | InvalidParameterSpecException | InvalidKeySpecException |
                InvalidKeyException | SignatureException e)
        {
            throw new RuntimeException("Error while initializing the parameters for the signature verification", e);
        }

        // Step 21: Let storedSignCount be the stored signature counter value associated with credential.id.
        // If authData.signCount is nonzero or storedSignCount is nonzero, then run the following sub-step:
        //  If authData.signCount is
        //      greater than storedSignCount:
        //          Update storedSignCount to be the value of authData.signCount.
        //      less than or equal to storedSignCount:
        //          This is a signal that the authenticator may be cloned, i.e. at least two copies of the credential
        //          private key may exist and are being used in parallel. Relying Parties should incorporate this
        //          information into their risk scoring. Whether the Relying Party updates storedSignCount in this case,
        //          or not, or fails the authentication ceremony or not, is Relying Party-specific.
        if (configuration.getEnableValidationOfSignatureCounter())
        {
            String deviceId = deviceAttributes.getDeviceId();

            byte[] singCountBytes = Arrays.copyOfRange(authData, 33, 37);
            int signCount = new BigInteger(singCountBytes).intValue();
            int storedSignCount = Integer.parseInt(bucket.getAttributes(deviceId,
                    BUCKET_WEBAUTHN_STORED_SIGNED_COUNT).get(STORED_SIGN_COUNT_ATTRIBUTE).toString());

            if (storedSignCount > 0 && signCount > storedSignCount)
            {
                // Update storedSignCount
                bucket.storeAttributes(deviceId, BUCKET_WEBAUTHN_STORED_SIGNED_COUNT,
                        ImmutableMap.of(STORED_SIGN_COUNT_ATTRIBUTE, signCount));
            }
            else if (signCount <= storedSignCount)
            {
                _logger.debug("Stored signature count for device is higher or equal to the signature count " +
                        "maintained by the device. This might indicate that the authenticator device may be " +
                        "cloned i.e. at least two copies of the credential private key may exist and are " +
                        "being used in parallel. The stored sign count will not be updated.");


                throw exceptionFactory.badRequestException(GENERIC_ERROR, "error.authentication-failed");
            }
        }

        return true;
    }

    private static byte[] getSHA256Hash(byte[] byteArray)
    {
        try
        {
            return MessageDigest.getInstance("SHA-256").digest(byteArray);
        }
        catch (NoSuchAlgorithmException e)
        {
            throw new RuntimeException("Could not load SHA-256 algorithm", e);
        }
    }

    // Rightmost bit in byte has position 0
    private static boolean isNthBitSet(byte byteToCheck, int position)
    {
        byte allZeroByte = 0b00000000;

        return ((allZeroByte ^ (1 << position)) & byteToCheck) >> position == 1;
    }

    public static Map<String, String> validateRegistration(WebAuthnPluginConfiguration configuration,
                                                           WebAuthnRegistrationRequestModel.Post request,
                                                           String challenge)
    {
        ExceptionFactory exceptionFactory = configuration.getExceptionFactory();
        Json json = configuration.getJson();

        // https://www.w3.org/TR/webauthn-2/#sctn-registering-a-new-credential

        // Step 6: Let C, the client data claimed as collected during the credential creation, be the result of running
        // an implementation-specific JSON parser on JSONtext.
        Map<String, Object> clientDataJsonAsMap = json.fromJson(new String(Base64.getDecoder().decode(
                request.getClientDataJSON()), StandardCharsets.UTF_8));

        // Step 7: Verify that the value of clientData.type is webauthn.create
        String clientDataType = clientDataJsonAsMap.get("type").toString();

        if (!clientDataType.equals(WEBAUTHN_CREATE))
        {
            _logger.debug("Failed to validate clientData.type, value: {}, expected value: {}",
                    clientDataType, WEBAUTHN_CREATE);

            throw exceptionFactory.badRequestException(GENERIC_ERROR, "error.registration-failed");
        }

        // Step 8: Verify that the value of clientData.challenge equals the base64url encoding of
        // PublicKeyCredentialCreationOptions.challenge
        String clientDataChallenge = clientDataJsonAsMap.get("challenge").toString();
        String base64EncodedChallengeUsedForRegistration = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(challenge.getBytes());

        if (!clientDataChallenge.equals(base64EncodedChallengeUsedForRegistration))
        {
            _logger.debug("Failed to validate clientData.challenge, value: {}, expected value: {}",
                    clientDataChallenge, base64EncodedChallengeUsedForRegistration);

            throw exceptionFactory.badRequestException(GENERIC_ERROR, "error.registration-failed");
        }

        // Step 9: Verify that the value of clienData.origin matches the Relying Party's origin
        try
        {
            String clientDataOrigin = new URI(clientDataJsonAsMap.get("origin").toString()).getHost();
            String baseUriHost = configuration.getAuthenticatorInformationProvider().getBaseUri().getHost();

            if (!clientDataOrigin.equals(baseUriHost))
            {
                _logger.debug("Failed to validate clientData.origin, value: {}, expected value: {}",
                        clientDataOrigin, baseUriHost);

                throw exceptionFactory.badRequestException(GENERIC_ERROR, "error.registration-failed");
            }
        }
        catch (URISyntaxException e)
        {
            throw exceptionFactory.badRequestException(GENERIC_ERROR, "Invalid URI in clientData.origin");
        }

        // Step 10: Verify that the value of clientData.tokenBinding.status matches the state of Token Binding for the
        // TLS connection over which the assertion was obtained. If Token Binding was used on that TLS connection, also
        // verify that clientData.tokenBinding.id matches the base64url encoding of the Token Binding ID for the
        // connection. This is optional and its absence suggest that the client doesn't supoort it.
        if (clientDataJsonAsMap.get("TokenBinding") != null)
        {
            _logger.debug("Failed to validate clientData.tokenBinding.status, Token Binding is not supported");

            throw exceptionFactory.badRequestException(GENERIC_ERROR, "error.registration-failed");
        }

        // Step 12: Perform CBOR decoding on the attestationObject field of the AuthenticatorAttestationResponse
        // structure to obtain the attestation statement format fmt, the authenticator data authData, and the
        // attestation statement attStmt
        ObjectMapper mapper = new ObjectMapper(new CBORFactory());
        AttestationObject attestationObject;

        try
        {
            JsonNode attestationObjectAsJsonNode = mapper.readTree(
                    Base64.getDecoder().decode(request.getAttestationObject()));
            attestationObject = new AttestationObject(attestationObjectAsJsonNode,
                    exceptionFactory.badRequestException(GENERIC_ERROR, "error.registration-failed"));
        }
        catch (IOException e)
        {
            throw new UncheckedIOException("Error when parsing attestation object from request.", e);
        }

        String attestationObjectFmt = attestationObject.getFormat();
        byte[] attestationObjectAuthData = attestationObject.getAuthenticatorData();

        // Currently the only  attestation supported is "none". If support for more types is going to be added, then
        // the attSmt verification should also be implemented
        if (!attestationObjectFmt.equals(Attestation.none.name()))
        {
            _logger.debug("Failed to validate attestationObject.fmt, supported attestation: none");

            throw exceptionFactory.badRequestException(GENERIC_ERROR, "error.registration-failed");
        }

        // Step 13: Verify that the rpIdHash in authData is the SHA-256 hash of the RP ID expected by the Relying
        // Party.
        byte[] authDataRpIdHash = Arrays.copyOfRange(attestationObjectAuthData, 0, 32);
        try
        {
            byte[] expectedRpIdHashFromConfig = getSHA256Hash(new URI(request.getRequestUrl()).getHost().getBytes());

            if (!Arrays.equals(authDataRpIdHash, expectedRpIdHashFromConfig))
            {
                _logger.debug("Failed to validate attestationObject.authData.rpIdHash");

                throw exceptionFactory.badRequestException(GENERIC_ERROR, "error.registration-failed");
            }
        }
        catch (URISyntaxException e)
        {
            throw exceptionFactory.badRequestException(GENERIC_ERROR, "Invalid URI in request");
        }

        // Step 14: Verify that the User Present bit of the flags in authData is set.
        byte authDataUserPresentFlag = Arrays.copyOfRange(attestationObjectAuthData, 32, 33)[0];

        if (!isNthBitSet(authDataUserPresentFlag, 0))
        {
            _logger.debug("Failed to validate attestationObject.authData UserPresent bit, flag is not set");

            throw exceptionFactory.badRequestException(GENERIC_ERROR, "error.registration-failed");
        }

        // Step 15: If user verification is required for this registration, verify that the User Verified bit of the
        // flags in authData is set.
        if (configuration.getUserVerifiedByTheAuthenticatorDevice())
        {
            if (!isNthBitSet(authDataUserPresentFlag, 2))
            {
                _logger.debug("Failed to validate attestationObject.authData UserVerified bit, flag is not set");

                throw exceptionFactory.badRequestException(GENERIC_ERROR, "error.registration-failed");
            }
        }

        // Step 16: Verify that the "alg" parameter in the credential public key in authData matches the alg
        // attribute of one of the items in options.pubKeyCredParams
        byte[] credentialIdLengtAsByteArray = Arrays.copyOfRange(attestationObjectAuthData, 53, 55);
        int credentialIdLength = ((credentialIdLengtAsByteArray[0] & 0xff) << 8) |
                (credentialIdLengtAsByteArray[1] & 0xff);
        String credentialId = Base64.getEncoder().encodeToString(Arrays.copyOfRange(
                attestationObjectAuthData, 55, 55 + credentialIdLength));

        CredentialPublicKey credentialPublicKey;

        try
        {
            JsonNode credentialPublicKeyAsJsonNode = mapper.readTree(Arrays.copyOfRange(
                    attestationObjectAuthData, 55 + credentialIdLength, attestationObjectAuthData.length));
            credentialPublicKey = new CredentialPublicKey(credentialPublicKeyAsJsonNode,
                    exceptionFactory.badRequestException(GENERIC_ERROR, "error.registration-failed"));
        }
        catch (IOException e)
        {
            throw new UncheckedIOException("Error when parsing attestation object from request.", e);
        }

        // The credentialPublicKey is of type COSE key. See https://tools.ietf.org/html/rfc8152#section-7.1
        if (!configuration.getAlgorithms().contains(
                Algorithm.getAlgorithmNameByCode(credentialPublicKey.getAlg())))
        {
            if (_logger.isDebugEnabled())
            {
                _logger.debug("Failed to validate attestationObject.authData.alg");
            }
            throw exceptionFactory.badRequestException(GENERIC_ERROR, "error.registration-failed");
        }

        return ImmutableMap.of(CREDENTIAL_ID_ATTRIBUTE, credentialId,
                CREDENTIAL_PUBLIC_KEY_ATTRIBUTE, credentialPublicKey.toString());
    }

    public static final class AttestationObject
    {
        private static final String FMT_FIELD = "fmt";
        private static final String ATT_STMT_FIELD = "attStmt";
        private static final String AUTH_DATA_FIELD = "authData";
        private final String _fmt;
        private final byte[] _authData;
        private final byte[] _attStmt;

        public AttestationObject(@Nullable JsonNode attestationObject, RuntimeException exception)
        {
            if (attestationObject.isNull())
            {
                throw exception;
            }
            else
            {
                _fmt = attestationObject.get(FMT_FIELD).textValue();

                try
                {
                    _authData = attestationObject.get(AUTH_DATA_FIELD).binaryValue();
                    _attStmt = attestationObject.get(ATT_STMT_FIELD).binaryValue();
                }
                catch (IOException e)
                {
                    throw new UncheckedIOException(
                            "Error, invalid authData field in the attestationObject of the request.", e);
                }
            }
        }

        @SuppressWarnings("unused")
        public byte[] getAttestationStatement()
        {
            return _attStmt;
        }

        public String getFormat()
        {
            return _fmt;
        }

        public byte[] getAuthenticatorData()
        {
            return _authData;
        }
    }

    public static final class CredentialPublicKey
    {
        private static final String KTY_FIELD = "1";
        private static final String ALG_FIELD = "3";
        private static final String CRV_FIELD = "-1";
        private static final String X_COORDINATE_FIELD = "-2";
        private static final String Y_COORDINATE_FIELD = "-3";
        private final JsonNode _credentialPublicKey;
        private final int _kty;
        private final int _alg;
        private final String _crv;
        private final String _xCoordinate;
        private final String _yCoordinate;

        public CredentialPublicKey(@Nullable JsonNode credentialPublicKey, RuntimeException exception)
        {
            if (credentialPublicKey.isNull())
            {
                throw exception;
            }
            else
            {
                _credentialPublicKey = credentialPublicKey;
                _kty = credentialPublicKey.get(KTY_FIELD).asInt();
                _alg = credentialPublicKey.get(ALG_FIELD).asInt();
                _crv = credentialPublicKey.get(CRV_FIELD).textValue();
                _xCoordinate = credentialPublicKey.get(X_COORDINATE_FIELD).textValue();
                _yCoordinate = credentialPublicKey.get(Y_COORDINATE_FIELD).textValue();
            }
        }

        @SuppressWarnings("unused")
        public int getKty()
        {
            return _kty;
        }

        public int getAlg()
        {
            return _alg;
        }

        @SuppressWarnings("unused")
        public String getCrv()
        {
            return _crv;
        }

        public String getXCoordinate()
        {
            return _xCoordinate;
        }

        public String getYCoordinate()
        {
            return _yCoordinate;
        }

        @Override
        public String toString()
        {
            return _credentialPublicKey.toString();
        }
    }
}