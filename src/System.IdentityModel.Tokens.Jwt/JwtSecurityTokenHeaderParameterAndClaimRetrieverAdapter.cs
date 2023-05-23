// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Tokens;

namespace System.IdentityModel.Tokens.Jwt
{
    /// <summary>
    /// Adapts a <see cref="JwtSecurityToken"/> to a <see cref="IHeaderParameterAndPayloadClaimRetriever"/>.
    /// </summary>
    public  class JwtSecurityTokenHeaderParameterAndClaimRetrieverAdapter : IHeaderParameterAndPayloadClaimRetriever
    {
        /// <summary>
        /// Creates an instance of a <see cref="JwtSecurityTokenHeaderParameterAndClaimRetrieverAdapter"/>
        /// </summary>
        /// <param name="jwtSecurityToken">The <see cref="JwtSecurityToken"/> to create a <see cref="JwtSecurityTokenHeaderParameterAndClaimRetrieverAdapter"/> from.</param>
        public JwtSecurityTokenHeaderParameterAndClaimRetrieverAdapter(JwtSecurityToken jwtSecurityToken)
        {
            if (jwtSecurityToken == null)
                throw LogHelper.LogArgumentNullException(nameof(jwtSecurityToken));

            HeaderParameters = new JwtSecurityTokenHeaderParameterRetriever(jwtSecurityToken.Header);
            PayloadClaims = new JwtSecurityTokenPayloadClaimsRetriever(jwtSecurityToken.Payload);

            if (jwtSecurityToken.InnerToken != null)
                InnerHeaderParameterAndClaimRetriever = new JwtSecurityTokenHeaderParameterAndClaimRetrieverAdapter(jwtSecurityToken.InnerToken);
        }

        /// <inheritdoc/>
        public IHeaderParameterRetriever HeaderParameters { get; }

        /// <inheritdoc/>
        public IPayloadClaimRetriever PayloadClaims { get; }

        /// <inheritdoc/>
        public IHeaderParameterAndPayloadClaimRetriever InnerHeaderParameterAndClaimRetriever { get; }

    }
}
