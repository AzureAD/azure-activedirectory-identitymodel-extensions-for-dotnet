//-----------------------------------------------------------------------
// Copyright (c) Microsoft Open Technologies, Inc.
// All Rights Reserved
// Apache License 2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// 
// http://www.apache.org/licenses/LICENSE-2.0
// 
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//-----------------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IdentityModel.Tokens;

namespace Microsoft.IdentityModel.Protocols
{
    /// <summary>
    /// Contains a set of parameters that are used by a <see cref="SecurityTokenHandler"/> when validating a <see cref="SecurityToken"/>.
    /// </summary>
    /// <remarks>These parameters are based from: http://openid.net/specs/openid-connect-core-1_0.html#IDToken </remarks>
    public class OpenIdConnectValidationParameters
    {
        private List<string> requiredClaims = new List<string> { JwtRegisteredClaimNames.Aud, JwtRegisteredClaimNames.Exp, JwtRegisteredClaimNames.Iat, JwtRegisteredClaimNames.Iss, JwtRegisteredClaimNames.Sub };
        private string _responseType;
        /// <summary>
        /// Creates an instance of <see cref="OpenIdConnectValidationParameters"/> with defaults:

        /// RequireAcr: false
        /// RequireAmr: false
        /// RequireAuthTime: false
        /// RequireAzp: false
        /// RequireNonce: true
        /// ResponseType = <see cref="OpenIdConnectMessage.DefaultResponseType"/>
        /// </summary>
        public OpenIdConnectValidationParameters()
        {
            RequireAcr = false;
            RequireAmr = false;
            RequireAuthTime = false;
            RequireAzp = false;
            RequireNonce = true;
            ResponseType = OpenIdConnectMessage.DefaultResponseType;
        }

        public string AuthorizationCode { }
        public string Nonce { get; set; }

        /// <summary>
        /// Gets or sets a value indicating if an 'acr' claim is required.
        /// </summary>
        [DefaultValue(false)]
        public bool RequireAcr { get; set; }

        /// <summary>
        /// Gets or sets a value indicating if an 'amr' claim is required.
        /// </summary>
        [DefaultValue(false)]
        public bool RequireAmr { get; set; }

        /// <summary>
        /// Gets or sets a value indicating if an 'auth_time' claim is required.
        /// </summary>
        [DefaultValue(false)]
        public bool RequireAuthTime { get; set; }

        /// <summary>
        /// Gets or sets a value indicating if an 'azp' claim is required.
        /// </summary>
        [DefaultValue(false)]
        public bool RequireAzp { get; set; }

        /// <summary>
        /// Gets or sets a value indicating if a 'nonce' claim is required.
        /// </summary>
        [DefaultValue(true)]
        public bool RequireNonce { get; set; }

        /// <summary>
        /// Gets or sets the ResponseType. This is used by <see cref="OpenIdConnectProtocolValidator.Validate"/>
        /// </summary>
        /// <exception cref="ArgumentNullException">if 'ResponseType' is null or whitespace.</exception>
        public string ResponseType
        {
            get
            {
                return _responseType;
            }
            set
            {
                if (string.IsNullOrWhiteSpace(value))
                    throw new ArgumentNullException("ResponeType");

                _responseType = value;
            }
        }

    }
}
