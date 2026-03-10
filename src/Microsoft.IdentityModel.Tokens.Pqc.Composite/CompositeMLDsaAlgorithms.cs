// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#nullable enable

using System.Diagnostics.CodeAnalysis;

namespace Microsoft.IdentityModel.Tokens.Pqc.Composite;

/// <summary>
/// Algorithm identifiers for composite ML-DSA signatures as defined in
/// draft-ietf-jose-pq-composite-sigs-01.
/// </summary>
/// <remarks>
/// These identifiers pair ML-DSA (post-quantum) with ECDSA or EdDSA (traditional)
/// to provide hybrid PQ/T composite signatures for JOSE.
/// </remarks>
[Experimental("MSIDENT2001")]
public static class CompositeMLDsaAlgorithms
{
    // ECDSA composite algorithms

    /// <summary>
    /// Composite signature with ML-DSA-44 and ECDSA using P-256 curve and SHA-256.
    /// Pre-hash: SHA-256.
    /// </summary>
    public const string MlDsa44Es256 = "ML-DSA-44-ES256";

    /// <summary>
    /// Composite signature with ML-DSA-65 and ECDSA using P-256 curve and SHA-256.
    /// Pre-hash: SHA-512.
    /// </summary>
    public const string MlDsa65Es256 = "ML-DSA-65-ES256";

    /// <summary>
    /// Composite signature with ML-DSA-87 and ECDSA using P-384 curve and SHA-384.
    /// Pre-hash: SHA-512.
    /// </summary>
    public const string MlDsa87Es384 = "ML-DSA-87-ES384";

    // EdDSA composite algorithms

    /// <summary>
    /// Composite signature with ML-DSA-44 and Ed25519.
    /// Pre-hash: SHA-512.
    /// </summary>
    /// <remarks>
    /// EdDSA composite variants are not yet supported by the .NET runtime.
    /// Using this algorithm will throw <see cref="System.PlatformNotSupportedException"/>.
    /// </remarks>
    public const string MlDsa44Ed25519 = "ML-DSA-44-Ed25519";

    /// <summary>
    /// Composite signature with ML-DSA-65 and Ed25519.
    /// Pre-hash: SHA-512.
    /// </summary>
    /// <remarks>
    /// EdDSA composite variants are not yet supported by the .NET runtime.
    /// Using this algorithm will throw <see cref="System.PlatformNotSupportedException"/>.
    /// </remarks>
    public const string MlDsa65Ed25519 = "ML-DSA-65-Ed25519";

    /// <summary>
    /// Composite signature with ML-DSA-87 and Ed448.
    /// Pre-hash: SHAKE-256.
    /// </summary>
    /// <remarks>
    /// EdDSA composite variants are not yet supported by the .NET runtime.
    /// Using this algorithm will throw <see cref="System.PlatformNotSupportedException"/>.
    /// </remarks>
    public const string MlDsa87Ed448 = "ML-DSA-87-Ed448";
}
