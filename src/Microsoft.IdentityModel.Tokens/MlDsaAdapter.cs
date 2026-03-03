// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Security.Cryptography;
using Microsoft.IdentityModel.Logging;

namespace Microsoft.IdentityModel.Tokens;

/// <summary>
/// Provides helper methods for creating <see cref="MLDsa"/> instances from JWK parameters.
/// </summary>
#if NET8_0_OR_GREATER
[System.Diagnostics.CodeAnalysis.Experimental("SYSLIB5006", UrlFormat = "https://aka.ms/dotnet-warnings/{0}")]
#endif
internal static class MlDsaAdapter
{
    /// <summary>
    /// Creates an <see cref="MLDsa"/> instance from a <see cref="JsonWebKey"/>.
    /// </summary>
    /// <param name="jsonWebKey">The JWK containing ML-DSA key material.</param>
    /// <param name="usePrivateKey">Whether to include the private key (seed).</param>
    /// <returns>An <see cref="MLDsa"/> instance.</returns>
    internal static MLDsa CreateMlDsa(JsonWebKey jsonWebKey, bool usePrivateKey)
    {
        if (jsonWebKey == null)
            throw LogHelper.LogArgumentNullException(nameof(jsonWebKey));

        if (string.IsNullOrEmpty(jsonWebKey.Pub))
            throw LogHelper.LogExceptionMessage(
                new ArgumentException(
                    LogHelper.FormatInvariant(LogMessages.IDX10700, LogHelper.MarkAsNonPII(nameof(JsonWebKey)), LogHelper.MarkAsNonPII(nameof(jsonWebKey.Pub)))));

        MLDsaAlgorithm algorithm = GetMLDsaAlgorithm(jsonWebKey.Alg);

        if (usePrivateKey)
        {
            if (string.IsNullOrEmpty(jsonWebKey.Priv))
                throw LogHelper.LogExceptionMessage(
                    new ArgumentException(
                        LogHelper.FormatInvariant(LogMessages.IDX10700, LogHelper.MarkAsNonPII(nameof(JsonWebKey)), LogHelper.MarkAsNonPII(nameof(jsonWebKey.Priv)))));

            byte[] seed = Base64UrlEncoder.DecodeBytes(jsonWebKey.Priv);
            return MLDsa.ImportMLDsaPrivateSeed(algorithm, seed);
        }

        byte[] publicKey = Base64UrlEncoder.DecodeBytes(jsonWebKey.Pub);
        return MLDsa.ImportMLDsaPublicKey(algorithm, publicKey);
    }

    /// <summary>
    /// Maps a JWK algorithm string to the corresponding <see cref="MLDsaAlgorithm"/>.
    /// </summary>
    internal static MLDsaAlgorithm GetMLDsaAlgorithm(string algorithm)
    {
        return algorithm switch
        {
            SecurityAlgorithms.MlDsa44 => MLDsaAlgorithm.MLDsa44,
            SecurityAlgorithms.MlDsa65 => MLDsaAlgorithm.MLDsa65,
            SecurityAlgorithms.MlDsa87 => MLDsaAlgorithm.MLDsa87,
            _ => throw LogHelper.LogArgumentException<ArgumentException>(nameof(algorithm), LogMessages.IDX10652, algorithm)
        };
    }
}
