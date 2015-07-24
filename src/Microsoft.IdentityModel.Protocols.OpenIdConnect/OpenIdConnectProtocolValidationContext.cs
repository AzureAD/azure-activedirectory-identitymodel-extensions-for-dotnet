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

namespace Microsoft.IdentityModel.Protocols.OpenIdConnect
{
    /// <summary>
    /// A context that is used by a <see cref="OpenIdConnectProtocolValidator"/> when validating a JwtSecurityToken.
    /// to ensure it compliant with  http://openid.net/specs/openid-connect-core-1_0.html#IDToken .
    /// </summary>
    public class OpenIdConnectProtocolValidationContext
    {
        /// <summary>
        /// Creates an instance of <see cref="OpenIdConnectProtocolValidationContext"/>
        /// </summary>
        public OpenIdConnectProtocolValidationContext()
        {
        }

        /// <summary>
        /// Gets or sets the 'authorizationcode'.
        /// </summary>
        public string AuthorizationCode { get; set; }

        /// <summary>
        /// Gets or sets the 'nonce'
        /// </summary>
        public string Nonce { get; set; }
    }
}
