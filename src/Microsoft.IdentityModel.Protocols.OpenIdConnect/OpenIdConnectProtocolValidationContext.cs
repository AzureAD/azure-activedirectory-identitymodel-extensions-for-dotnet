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
using System.IdentityModel.Tokens.Jwt;

namespace Microsoft.IdentityModel.Protocols.OpenIdConnect
{
    /// <summary>
    /// A context that is used by a <see cref="OpenIdConnectProtocolValidator"/> when validating an OpenIdConnect Response
    /// to ensure it compliant with http://openid.net/specs/openid-connect-core-1_0.html.
    /// </summary>
    public class OpenIdConnectProtocolValidationContext
    {
        /// <summary>
        /// Creates an instance of <see cref="OpenIdConnectProtocolValidationContext"/>
        /// </summary>
        public OpenIdConnectProtocolValidationContext() {}

        /// <summary>
        /// Gets or sets the 'code' to validate.
        /// </summary>
        /// Obsolete - Will be removed in beta8, the Property: ProtocolMessage will have the 'code'
        public string AuthorizationCode { get; set; }

        /// <summary>
        /// Gets or sets the 'client_id'.
        /// </summary>
        public string ClientId { get; set; }

        /// <summary>
        /// Gets or sets the 'nonce' that was sent with the 'Request'.
        /// </summary>
        public string Nonce { get; set; }

        /// <summary>
        /// Gets or sets the <see cref="OpenIdConnectMessage"/> that represents the 'Response'.
        /// </summary>
        public OpenIdConnectMessage ProtocolMessage { get; set; }

        /// <summary>
        /// Gets or sets the state that was sent with the 'Request'.
        /// </summary>
        public string State { get; set; }

        /// <summary>
        /// Gets or sets a validated id_token.
        /// </summary>
        public JwtSecurityToken IdToken { get; set; }
    }
}
