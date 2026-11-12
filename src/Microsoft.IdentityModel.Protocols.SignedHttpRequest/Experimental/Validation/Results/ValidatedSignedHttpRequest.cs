// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens.Experimental;

#nullable enable
namespace Microsoft.IdentityModel.Protocols.SignedHttpRequest
{
    /// <summary>Contains artifacts from successfully validating an SHR and its embedded access token.</summary>
    public class ValidatedSignedHttpRequest
    {
        /// <summary>Initializes a successful SHR validation artifact.</summary>
        /// <param name="signedHttpRequest">The validated SHR.</param>
        /// <param name="accessTokenValidationResult">The validated embedded access token.</param>
        public ValidatedSignedHttpRequest(JsonWebToken signedHttpRequest, ValidatedToken accessTokenValidationResult)
        {
            ValidatedToken = signedHttpRequest ?? throw new ArgumentNullException(nameof(signedHttpRequest));
            AccessTokenValidationResult = accessTokenValidationResult ?? throw new ArgumentNullException(nameof(accessTokenValidationResult));
        }

        /// <summary>Gets the validated SHR, including its signing key.</summary>
        public JsonWebToken ValidatedToken { get; }

        /// <summary>Gets the original compact SHR.</summary>
        public string SignedHttpRequest => ValidatedToken.EncodedToken;

        /// <summary>Gets the experimental access-token validation result and its claims identity.</summary>
        public ValidatedToken AccessTokenValidationResult { get; }
    }
}
