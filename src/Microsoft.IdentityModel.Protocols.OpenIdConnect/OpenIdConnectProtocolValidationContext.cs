// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Tokens;

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
        /// Gets or sets the response received from userinfo_endpoint.
        /// </summary>
        public string UserInfoEndpointResponse { get; set; }

        /// <summary>
        /// Gets or sets the header parameter and payload claims retriever.
        /// </summary>
        public IHeaderParameterAndPayloadClaimRetriever HeaderParameterAndPayloadClaimRetriever { get; set; }

        private JwtSecurityToken _jwtSecurityToken;

        /// <summary>
        /// This id_token is assumed to have audience, issuer, lifetime and signature validated.
        /// </summary>
        public JwtSecurityToken ValidatedIdToken
        {
            get
            {
                if (_jwtSecurityToken == null)
                {
                    if (HeaderParameterAndPayloadClaimRetriever == null)
                        return null;

                    _jwtSecurityToken = new JwtSecurityToken(HeaderParameterAndPayloadClaimRetriever.GetStringRepresentation());
                }

                return _jwtSecurityToken;
            }
            set
            {
                _jwtSecurityToken = value;
            }
        }
    }
}
