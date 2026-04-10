// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using Microsoft.IdentityModel.Tokens;

namespace Microsoft.IdentityModel.Dpop;

/// <summary>
/// Contains options for creating and validating DPoP proofs according to RFC 9449.
/// </summary>
public class DPoPProofOptions
{
    /// <summary>
    /// Gets or sets the maximum age a DPoP proof can be, measured in seconds.
    /// Default is 60 seconds as suggested by the RFC.
    /// </summary>
    public int MaxProofAgeInSeconds { get; set; } = 60;

    /// <summary>
    /// Gets or sets the signature credentials used to sign the DPoP proof.
    /// This property is required and must be set before creating a proof.
    /// </summary>
    public SigningCredentials SigningCredentials { get; set; }

    /// <summary>
    /// Gets or sets the token validation parameters for validating DPoP proofs.
    /// When null, default validation parameters are used.
    /// </summary>
    public TokenValidationParameters ValidationParameters { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether a nonce claim should be included in the DPoP proof.
    /// </summary>
    public bool IncludeNonce { get; set; } = false;

    /// <summary>
    /// Gets or sets the value of the nonce claim if IncludeNonce is true.
    /// If not set, a random nonce will be generated.
    /// </summary>
    public string Nonce { get; set; }

#if NET8_0_OR_GREATER
    /// <summary>
    /// Gets or sets the time provider used to get the current time.
    /// </summary>
    public TimeProvider TimeProvider { get; set; } = TimeProvider.System;
#endif
}
