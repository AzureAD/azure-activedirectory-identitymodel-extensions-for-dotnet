// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;

namespace Microsoft.IdentityModel.Dpop;

/// <summary>
/// Options for server-side DPoP proof validation per RFC 9449 §4.3.
/// </summary>
public class DPoPValidationOptions
{
    /// <summary>
    /// Gets or sets the set of allowed signing algorithms for DPoP proofs.
    /// Only asymmetric algorithms are permitted; symmetric (HMAC) and "none" are always rejected.
    /// Default: ES256, PS256, RS256.
    /// </summary>
    public ISet<string> AllowedSigningAlgorithms { get; set; }
        = new HashSet<string>(StringComparer.Ordinal) { "ES256", "PS256", "RS256" };

    /// <summary>
    /// Gets or sets the maximum proof lifetime in seconds, measured from the <c>iat</c> claim.
    /// Default: 300 (5 minutes).
    /// </summary>
    public int MaxLifetimeInSeconds { get; set; } = 300;

    /// <summary>
    /// Gets or sets the clock skew tolerance in seconds.
    /// Applied both for proofs that are slightly too old and for proofs issued slightly in the future.
    /// Default: 300 (5 minutes).
    /// </summary>
    public int ClockSkewInSeconds { get; set; } = 300;

    /// <summary>
    /// Gets or sets the expected nonce value (RP-provided).
    /// When non-null, the DPoP proof must contain a matching <c>nonce</c> claim.
    /// When null, nonce validation is skipped.
    /// Default: null.
    /// </summary>
    public string ExpectedNonce { get; set; }

    /// <summary>
    /// Gets or sets the optional replay cache for <c>jti</c> (JWT ID) replay detection.
    /// When set, each proof's jti is checked against the cache to prevent reuse.
    /// When null, jti replay detection is skipped.
    /// Default: null.
    /// </summary>
    public IJtiReplayCache JtiReplayCache { get; set; }

#if NET8_0_OR_GREATER
    /// <summary>
    /// Gets or sets the time provider used for timestamp validation.
    /// Override for unit testing.
    /// Default: <see cref="TimeProvider.System"/>.
    /// </summary>
    public TimeProvider TimeProvider { get; set; } = TimeProvider.System;
#endif
}
