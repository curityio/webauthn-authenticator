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
import java.util.Optional;

final class WebAuthnAuthenticationRequestModel
{
    @Valid
    @Nullable
    private final Post _postRequestModel;

    WebAuthnAuthenticationRequestModel(Request request)
    {
        _postRequestModel = request.isPostRequest() ? new Post(request) : null;
    }

    Post getPostRequestModel()
    {
        return Optional.ofNullable(_postRequestModel).orElseThrow(() ->
                new RuntimeException("Post RequestModel does not exist"));
    }

    static class Post
    {
        private static final String USERNAME_PARAM = "username";

        @NotBlank(message = "validation.error.username.required")
        private final String _username;

        Post(Request request)
        {
            _username = request.getFormParameterValueOrError(USERNAME_PARAM);
        }

        String getUsername()
        {
            return _username;
        }
    }
}
