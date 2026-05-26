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

    private int _maxLifetimeInSeconds = DPoPConstants.DefaultMaxLifetimeInSeconds;
    private int _clockSkewInSeconds = DPoPConstants.DefaultClockSkewInSeconds;
    private int _maxProofTokenSizeInBytes = DPoPConstants.DefaultMaxProofTokenSizeInBytes;
    private int _maxRsaKeySizeInBits = DPoPConstants.DefaultMaxRsaKeySizeInBits;
    private int _minRsaKeySizeInBits = DPoPConstants.DefaultMinRsaKeySizeInBits;

    /// <summary>
    /// Gets or sets the maximum proof lifetime in seconds, measured from the <c>iat</c> claim.
    /// Default: <see cref="DPoPConstants.DefaultMaxLifetimeInSeconds"/>.
    /// </summary>
    /// <exception cref="ArgumentOutOfRangeException">Thrown when set to a value less than 1.</exception>
    public int MaxLifetimeInSeconds
    {
        get => _maxLifetimeInSeconds;
        set => _maxLifetimeInSeconds = value < 1
            ? throw new ArgumentOutOfRangeException(nameof(value), value, "MaxLifetimeInSeconds must be greater than zero.")
            : value;
    }

    /// <summary>
    /// Gets or sets the maximum DPoP proof JWT size in bytes.
    /// Proofs exceeding this size are rejected before parsing.
    /// Default: <see cref="DPoPConstants.DefaultMaxProofTokenSizeInBytes"/>.
    /// </summary>
    /// <exception cref="ArgumentOutOfRangeException">Thrown when set to a value less than 1.</exception>
    public int MaxProofTokenSizeInBytes
    {
        get => _maxProofTokenSizeInBytes;
        set => _maxProofTokenSizeInBytes = value < 1
            ? throw new ArgumentOutOfRangeException(nameof(value), value, "MaxProofTokenSizeInBytes must be greater than zero.")
            : value;
    }

    /// <summary>
    /// Gets or sets the maximum RSA modulus size in bits permitted for DPoP proof signing keys.
    /// Bounds the cost of verifying client-controlled keys.
    /// Default: <see cref="DPoPConstants.DefaultMaxRsaKeySizeInBits"/>.
    /// </summary>
    /// <exception cref="ArgumentOutOfRangeException">Thrown when set to a value less than 1.</exception>
    public int MaxRsaKeySizeInBits
    {
        get => _maxRsaKeySizeInBits;
        set => _maxRsaKeySizeInBits = value < 1
            ? throw new ArgumentOutOfRangeException(nameof(value), value, "MaxRsaKeySizeInBits must be greater than zero.")
            : value;
    }

    /// <summary>
    /// Gets or sets the minimum RSA modulus size in bits required for DPoP proof signing keys.
    /// Default: <see cref="DPoPConstants.DefaultMinRsaKeySizeInBits"/>.
    /// </summary>
    /// <exception cref="ArgumentOutOfRangeException">Thrown when set to a value less than 1.</exception>
    public int MinRsaKeySizeInBits
    {
        get => _minRsaKeySizeInBits;
        set => _minRsaKeySizeInBits = value < 1
            ? throw new ArgumentOutOfRangeException(nameof(value), value, "MinRsaKeySizeInBits must be greater than zero.")
            : value;
    }

    /// <summary>
    /// Gets or sets the clock skew tolerance in seconds.
    /// Applied both for proofs that are slightly too old and for proofs issued slightly in the future.
    /// Default: <see cref="DPoPConstants.DefaultClockSkewInSeconds"/>.
    /// </summary>
    /// <exception cref="ArgumentOutOfRangeException">Thrown when set to a negative value.</exception>
    public int ClockSkewInSeconds
    {
        get => _clockSkewInSeconds;
        set => _clockSkewInSeconds = value < 0
            ? throw new ArgumentOutOfRangeException(nameof(value), value, "ClockSkewInSeconds must be non-negative.")
            : value;
    }

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
