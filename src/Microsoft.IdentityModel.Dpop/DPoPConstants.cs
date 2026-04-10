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
    /// The DPoP HTTP header name.
    /// </summary>
    public const string DPoPHeaderName = "DPoP";

    /// <summary>
    /// The DPoP HTTP WWW-Authenticate challenge parameter.
    /// </summary>
    public const string DPoPChallengeParameter = "DPoP";

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

    /// <summary>
    /// The key identifier for the DPoP proof confirmation claim in the access token.
    /// </summary>
    public const string ConfirmationClaimDPoPKeyId = "jkt";

    /// <summary>
    /// The DPoP confirmation claim name.
    /// </summary>
    public const string ConfirmationClaimType = "cnf";
}
