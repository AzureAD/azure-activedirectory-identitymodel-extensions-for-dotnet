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
    /// A set of parameters that are used to define validation requirements. Used by a <see cref="OpenIdConnectProtocolValidator"/> when validating a <see cref="JwtSecurityToken"/>
    /// to enusre it compliant with  http://openid.net/specs/openid-connect-core-1_0.html#IDToken .
    /// </summary>
    public class OpenIdConnectProtocolValidationParameters
    {
        private string _responseType;
        private IDictionary<string, string> _algorithmMap = 
            new Dictionary<string, string>
            {
                { JwtAlgorithms.ECDSA_SHA256, "SHA256" },
                { JwtAlgorithms.RSA_SHA256, "SHA256" },
                { JwtAlgorithms.HMAC_SHA256, "SHA256" },
                { JwtAlgorithms.ECDSA_SHA384, "SHA384" },
                { JwtAlgorithms.RSA_SHA384, "SHA384" },
                { JwtAlgorithms.HMAC_SHA384, "SHA384" },
                { JwtAlgorithms.ECDSA_SHA512, "SHA512" },
                { JwtAlgorithms.RSA_SHA512, "SHA512" },
                { JwtAlgorithms.HMAC_SHA512, "SHA512" },
          };

        /// <summary>
        /// Creates an instance of <see cref="OpenIdConnectProtocolValidationParameters"/> with defaults:
        /// RequireAcr: false
        /// RequireAmr: false
        /// RequireAuthTime: false
        /// RequireAzp: false
        /// RequireNonce: true
        /// ResponseType = <see cref="OpenIdConnectMessage.DefaultResponseType"/>
        /// </summary>
        public OpenIdConnectProtocolValidationParameters()
        {
            RequireAcr = false;
            RequireAmr = false;
            RequireAuthTime = false;
            RequireAzp = false;
            RequireNonce = true;
            ResponseType = OpenIdConnectMessage.DefaultResponseType;
        }

        /// <summary>
        /// Gets or sets the algoritm mapping between Jwt and .Net
        /// a <see cref="IDictionary{TKey, TValue}"/> that contains mappings from the JWT namespace http://tools.ietf.org/html/draft-ietf-jose-json-web-algorithms-26 to .Net.
        /// </summary>
        /// <exception cref="ArgumentNullException">if 'AlgorithmMap' is null.</exception>
        public IDictionary<string, string> AlgorithmMap 
        {
            get
            {
                return _algorithmMap;
            }
            set
            {
                if (value == null)
                {
                    throw new ArgumentNullException("AlgorithmMap");
                }
                _algorithmMap = value;
            }
        }
        
        /// <summary>
        /// Gets or sets the 'authorizationcode'.
        /// </summary>
        public string AuthorizationCode { get; set; }
        
        /// <summary>
        /// Gets or sets the 'nonce'
        /// </summary>
        [DefaultValue((string)null)]
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
