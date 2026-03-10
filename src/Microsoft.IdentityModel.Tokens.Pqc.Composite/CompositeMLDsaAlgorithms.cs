// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#nullable enable

using System;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;

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
    /// Using this algorithm will throw <see cref="PlatformNotSupportedException"/>.
    /// </remarks>
    public const string MlDsa44Ed25519 = "ML-DSA-44-Ed25519";

    /// <summary>
    /// Composite signature with ML-DSA-65 and Ed25519.
    /// Pre-hash: SHA-512.
    /// </summary>
    /// <remarks>
    /// EdDSA composite variants are not yet supported by the .NET runtime.
    /// Using this algorithm will throw <see cref="PlatformNotSupportedException"/>.
    /// </remarks>
    public const string MlDsa65Ed25519 = "ML-DSA-65-Ed25519";

    /// <summary>
    /// Composite signature with ML-DSA-87 and Ed448.
    /// Pre-hash: SHAKE-256.
    /// </summary>
    /// <remarks>
    /// EdDSA composite variants are not yet supported by the .NET runtime.
    /// Using this algorithm will throw <see cref="PlatformNotSupportedException"/>.
    /// </remarks>
    public const string MlDsa87Ed448 = "ML-DSA-87-Ed448";

    /// <summary>
    /// Returns <c>true</c> if the <paramref name="algorithm"/> is a known composite ML-DSA algorithm.
    /// </summary>
    /// <param name="algorithm">The JOSE algorithm identifier to check.</param>
    /// <returns><c>true</c> if the algorithm is a composite ML-DSA algorithm; otherwise <c>false</c>.</returns>
    public static bool IsCompositeAlgorithm(string algorithm)
    {
        return algorithm == MlDsa44Es256
            || algorithm == MlDsa65Es256
            || algorithm == MlDsa87Es384
            || algorithm == MlDsa44Ed25519
            || algorithm == MlDsa65Ed25519
            || algorithm == MlDsa87Ed448;
    }

    /// <summary>
    /// Gets the JOSE algorithm string for a <see cref="CompositeMLDsaAlgorithm"/>.
    /// </summary>
    /// <param name="algorithm">The .NET <see cref="CompositeMLDsaAlgorithm"/> instance.</param>
    /// <returns>The JOSE algorithm identifier.</returns>
    /// <exception cref="ArgumentException">Thrown if the algorithm is not recognised.</exception>
    public static string GetJoseAlgorithm(CompositeMLDsaAlgorithm algorithm)
    {
        if (algorithm == CompositeMLDsaAlgorithm.MLDsa44WithECDsaP256) return MlDsa44Es256;
        if (algorithm == CompositeMLDsaAlgorithm.MLDsa65WithECDsaP256) return MlDsa65Es256;
        if (algorithm == CompositeMLDsaAlgorithm.MLDsa87WithECDsaP384) return MlDsa87Es384;
        if (algorithm == CompositeMLDsaAlgorithm.MLDsa44WithEd25519) return MlDsa44Ed25519;
        if (algorithm == CompositeMLDsaAlgorithm.MLDsa65WithEd25519) return MlDsa65Ed25519;
        if (algorithm == CompositeMLDsaAlgorithm.MLDsa87WithEd448) return MlDsa87Ed448;

        throw new ArgumentException($"Unknown CompositeMLDsaAlgorithm: {algorithm}");
    }

    /// <summary>
    /// Gets the <see cref="CompositeMLDsaAlgorithm"/> for a JOSE algorithm string.
    /// </summary>
    /// <param name="algorithm">The JOSE algorithm identifier.</param>
    /// <returns>The corresponding <see cref="CompositeMLDsaAlgorithm"/>.</returns>
    /// <exception cref="ArgumentException">Thrown if the algorithm string is not recognised.</exception>
    public static CompositeMLDsaAlgorithm GetCompositeMLDsaAlgorithm(string algorithm)
    {
        return algorithm switch
        {
            MlDsa44Es256 => CompositeMLDsaAlgorithm.MLDsa44WithECDsaP256,
            MlDsa65Es256 => CompositeMLDsaAlgorithm.MLDsa65WithECDsaP256,
            MlDsa87Es384 => CompositeMLDsaAlgorithm.MLDsa87WithECDsaP384,
            MlDsa44Ed25519 => CompositeMLDsaAlgorithm.MLDsa44WithEd25519,
            MlDsa65Ed25519 => CompositeMLDsaAlgorithm.MLDsa65WithEd25519,
            MlDsa87Ed448 => CompositeMLDsaAlgorithm.MLDsa87WithEd448,
            _ => throw new ArgumentException($"Unknown composite algorithm: {algorithm}"),
        };
    }
}
