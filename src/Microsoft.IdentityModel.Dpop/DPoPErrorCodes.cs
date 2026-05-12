// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

namespace Microsoft.IdentityModel.Dpop;

/// <summary>
/// RFC 9449 error codes for DPoP validation failures.
/// </summary>
public static class DPoPErrorCodes
{
    /// <summary>The server requires a DPoP nonce.</summary>
    public const string UseDPoPNonce = "use_dpop_nonce";

    /// <summary>The token is invalid.</summary>
    public const string InvalidToken = "invalid_token";

    /// <summary>The request is invalid (e.g., missing DPoP proof).</summary>
    public const string InvalidRequest = "invalid_request";
}
