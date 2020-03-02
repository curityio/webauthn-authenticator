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
import se.curity.identityserver.sdk.service.UserPreferenceManager;
import se.curity.identityserver.sdk.web.Request;

import javax.validation.Valid;

final class WebAuthnSelectDeviceRequestModel
{
    @Valid
    @Nullable
    private final Post _postRequestModel;

    @Valid
    @Nullable
    private final Get _getRequestModel;

    WebAuthnSelectDeviceRequestModel(Request request, UserPreferenceManager userPreferenceManager)
    {
        _postRequestModel = request.isPostRequest() ? new Post(request, userPreferenceManager) : null;
        _getRequestModel = request.isGetRequest() ? new Get(userPreferenceManager) : null;
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

    Get getGetRequestModel()
    {
        if (_getRequestModel != null)
        {
            return _getRequestModel;
        }
        else
        {
            throw new NullPointerException("GET RequestModel does not exist");
        }
    }

    static class Get
    {
        private final String _username;

        Get(UserPreferenceManager userPreferenceManager)
        {
            _username = userPreferenceManager.getUsername();
        }

        String getUsername()
        {
            return _username;
        }
    }

    static class Post
    {
        static final String DEVICE_ID_PARAM = "deviceId";

        @NotBlank(message = "validation.error.username.required")
        private final String _username;

        @NotBlank(message = "validaton.error.device.required")
        private final String _deviceId;

        Post(Request request, UserPreferenceManager userPreferenceManager)
        {
            _username = userPreferenceManager.getUsername();
            _deviceId = request.getFormParameterValueOrError(DEVICE_ID_PARAM);
        }

        String getUsername()
        {
            return _username;
        }

        String getDeviceId()
        {
            return _deviceId;
        }
    }
}
