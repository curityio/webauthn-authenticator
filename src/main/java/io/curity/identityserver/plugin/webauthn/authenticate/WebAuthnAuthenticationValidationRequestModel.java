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

import org.hibernate.validator.constraints.NotBlank;
import se.curity.identityserver.sdk.Nullable;
import se.curity.identityserver.sdk.web.Request;

import javax.validation.Valid;

public final class WebAuthnAuthenticationValidationRequestModel
{
    @Valid
    @Nullable
    private final Post _postRequestModel;

    WebAuthnAuthenticationValidationRequestModel(Request request)
    {
        _postRequestModel = request.isPostRequest() ? new Post(request) : null;
    }

    Post getPostRequestModel()
    {
        if (_postRequestModel != null)
        {
            return _postRequestModel;
        }
        else
        {
            throw new NullPointerException("POST RequestModel does not exist");
        }
    }

    public final static class Post
    {
        private static final String ID_PARAM = "id";
        private static final String RAW_ID_PARAM = "rawId";
        private static final String AUTHENTICATOR_DATA_PARAM = "authenticatorData";
        private static final String CLIENT_DATA_JSON_PARAM = "clientDataJSON";
        private static final String SIGNATURE_PARAM = "signature";
        private static final String USER_HANDLE_PARAM = "userHandle";
        private static final String TYPE_PARAM = "type";

        @NotBlank(message = "validation.error.id.required")
        private final String _id;

        @NotBlank(message = "validation.error.rawId.required")
        private final String _rawId;

        @NotBlank(message = "validation.error.authenticatorData.required")
        private final String _authenticatorData;

        @NotBlank(message = "validation.error.clientDataJSON")
        private final String _clientDataJSON;

        @NotBlank(message = "validation.error.signature.required")
        private final String _signature;

        private final String _userHandle;

        @NotBlank(message = "validation.error.type")
        private final String _type;

        @NotBlank(message = "validation.error.url")
        private final String _requestUrl;

        Post(Request request)
        {
            _id = request.getFormParameterValueOrError(ID_PARAM);
            _rawId = request.getFormParameterValueOrError(RAW_ID_PARAM);
            _authenticatorData = request.getFormParameterValueOrError(AUTHENTICATOR_DATA_PARAM);
            _clientDataJSON = request.getFormParameterValueOrError(CLIENT_DATA_JSON_PARAM);
            _signature = request.getFormParameterValueOrError(SIGNATURE_PARAM);
            _userHandle = request.getFormParameterValueOrError(USER_HANDLE_PARAM);
            _type = request.getFormParameterValueOrError(TYPE_PARAM);
            _requestUrl = request.getUrl();
        }

        public String getId()
        {
            return _id;
        }

        public String getRawId()
        {
            return _rawId;
        }

        public String getAuthenticatorData()
        {
            return _authenticatorData;
        }

        public String getClientDataJSON()
        {
            return _clientDataJSON;
        }

        public String getSignature()
        {
            return _signature;
        }

        public String getUserHandle()
        {
            return _userHandle;
        }

        public String getType()
        {
            return _type;
        }

        public String getRequestUrl()
        {
            return _requestUrl;
        }
    }
}
