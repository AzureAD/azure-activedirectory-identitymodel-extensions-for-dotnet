// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System.Collections.Generic;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Tokens;

namespace System.IdentityModel.Tokens.Jwt
{
    internal class JwtSecurityTokenPayloadClaimsRetriever : IPayloadClaimRetriever
    {
        private readonly JwtPayload _payload;

        /// <summary>
        /// Creates an instance of a <see cref="JwtSecurityTokenPayloadClaimsRetriever"/>.
        /// </summary>
        /// <param name="payload">The <see cref="JwtPayload"/> to create the <see cref="JwtSecurityTokenPayloadClaimsRetriever"/> from.</param>
        public JwtSecurityTokenPayloadClaimsRetriever(JwtPayload payload)
        {
            _payload = payload ?? throw LogHelper.LogArgumentNullException(nameof(payload));
        }

        /// <inheritdoc/>
        public DateTime GetDateTimeValue(string claimType)
        {
            if (string.IsNullOrEmpty(claimType))
                throw LogHelper.LogArgumentNullException(nameof(claimType));

            return _payload.GetDateTime(claimType);
        }

        /// <inheritdoc/>
        public IList<string> GetStringCollection(string claimType)
        {
            if (string.IsNullOrEmpty(claimType))
                throw LogHelper.LogArgumentNullException(nameof(claimType));

            return _payload.GetIListClaims(claimType);
        }

        /// <inheritdoc/>
        public string GetStringValue(string claimType)
        {
            if (string.IsNullOrEmpty(claimType))
                throw LogHelper.LogArgumentNullException(nameof(claimType));

            return _payload.GetStandardClaim(claimType) ?? string.Empty;
        }

        /// <inheritdoc/>
        public bool TryGetValue(string claimType, out object value)
        {
            if (string.IsNullOrEmpty(claimType))
                throw LogHelper.LogArgumentNullException(nameof(claimType));

            return _payload.TryGetValue(claimType, out value);
        }
    }
}
