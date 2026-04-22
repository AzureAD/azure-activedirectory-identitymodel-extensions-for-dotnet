// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

namespace Microsoft.IdentityModel.Dpop;

/// <summary>
/// Constants for DPoP (Demonstrating Proof-of-Possession at the Application Layer) per RFC 9449.
/// </summary>
/// <remarks>
/// Claim types are in <see cref="DPoPClaimTypes"/>.
/// Error codes are in <see cref="DPoPErrorCodes"/>.
/// </remarks>
public static class DPoPConstants
{
    /// <summary>
    /// The DPoP token type.
    /// </summary>
    public const string DPoPTokenType = "DPoP";

    /// <summary>
    /// The required <c>typ</c> header value for DPoP proof JWTs.
    /// </summary>
    public const string DPoPProofTokenType = "dpop+jwt";

    /// <summary>
    /// The DPoP nonce HTTP header name.
    /// </summary>
    public const string DPoPNonceHeaderName = "DPoP-Nonce";
}
