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

import org.hibernate.validator.constraints.NotBlank;
import se.curity.identityserver.sdk.Nullable;
import se.curity.identityserver.sdk.web.Request;

import javax.validation.Valid;
import java.util.Optional;

public class WebAuthnRegistrationRequestModel
{
    @Valid
    @Nullable
    private final Post _postRequestModel;

    WebAuthnRegistrationRequestModel(Request request)
    {
        if (request.isPostRequest())
        {
            _postRequestModel = new Post(request);
        }
        else
        {
            _postRequestModel = null;
        }
    }

    Post getPostRequestModel()
    {
        return Optional.ofNullable(_postRequestModel).orElseThrow(() ->
                new RuntimeException("Post RequestModel does not exist"));
    }

    public static class Post
    {
        static final String ALIAS_PARAM = "alias";
        static final String ID_PARAM = "id";
        static final String TYPE_PARAM = "type";
        static final String RAW_ID_PARAM = "rawId";
        static final String CLIENT_EXTENSION_RESULTS_PARAM = "clientExtensionResults";
        static final String SIGNATURE_PARAM = "signature";
        static final String AUTHENTICATOR_DATA_PARAM = "authenticatorData";
        static final String CLIENT_DATA_JSON_PARAM = "clientDataJSON";
        static final String USER_HANDLE_PARAM = "userHandle";
        private static final String ATTESTATION_OBJECT = "attestationObject";
        private static final String CHALLENGE = "challenge";

        @NotBlank(message = "validation.error.alias.required")
        private final String _alias;

        @NotBlank(message = "validation.error.attestationObject.required")
        private final String _attestationObject;

        @NotBlank(message = "validation.error.id.required")
        private final String _id;

        @NotBlank(message = "validation.error.type.required")
        private final String _type;

        @NotBlank(message = "validation.error.rawId.required")
        private final String _rawId;

        @NotBlank(message = "validation.error.clientExtensionResults.required")
        private final String _clientExtensionResults;

        private final String _signature;

        private final String _authenticatorData;

        @NotBlank(message = "validation.error.clientDataJSON.required")
        private final String _clientDataJSON;

        private final String _userHandle;

        private final String _challenge;

        private final String _requestUrl;

        Post(Request request)
        {
            _alias = request.getFormParameterValueOrError(ALIAS_PARAM);
            _attestationObject = request.getFormParameterValueOrError(ATTESTATION_OBJECT);
            _id = request.getFormParameterValueOrError(ID_PARAM);
            _type = request.getFormParameterValueOrError(TYPE_PARAM);
            _rawId = request.getFormParameterValueOrError(RAW_ID_PARAM);
            _clientExtensionResults = request.getFormParameterValueOrError(CLIENT_EXTENSION_RESULTS_PARAM);
            _signature = request.getFormParameterValueOrError(SIGNATURE_PARAM);
            _authenticatorData = request.getFormParameterValueOrError(AUTHENTICATOR_DATA_PARAM);
            _clientDataJSON = request.getFormParameterValueOrError(CLIENT_DATA_JSON_PARAM);
            _userHandle = request.getFormParameterValueOrError(USER_HANDLE_PARAM);
            _challenge = request.getFormParameterValueOrError(CHALLENGE);
            _requestUrl = request.getUrl();
        }

        public String getAlias()
        {
            return _alias;
        }

        public String getId()
        {
            return _id;
        }

        public String getType()
        {
            return _type;
        }

        public String getRawId()
        {
            return _rawId;
        }

        public String getClientExtensionResults()
        {
            return _clientExtensionResults;
        }

        public String getSignature()
        {
            return _signature;
        }

        public String getAuthenticatorData()
        {
            return _authenticatorData;
        }

        public String getClientDataJSON()
        {
            return _clientDataJSON;
        }

        public String getUserHandle()
        {
            return _userHandle;
        }

        public String getAttestationObject()
        {
            return _attestationObject;
        }

        public String getChallenge()
        {
            return _challenge;
        }

        public String getRequestUrl()
        {
            return _requestUrl;
        }
    }
}
