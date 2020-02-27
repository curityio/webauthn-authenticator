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

import org.hibernate.validator.constraints.NotBlank;
import se.curity.identityserver.sdk.Nullable;
import se.curity.identityserver.sdk.service.AutoLoginManager;
import se.curity.identityserver.sdk.web.Request;

public class ContinueWithAutoLoginRequestModel
{
    @NotBlank
    private final String _nonceSessionKey;

    public ContinueWithAutoLoginRequestModel(Request request)
    {
        _nonceSessionKey = request.getFormParameterValueOrError(AutoLoginManager.FORM_NAME_TOKEN);
    }

    @Nullable
    public String getNonceSessionKey()
    {
        return _nonceSessionKey;
    }
}
