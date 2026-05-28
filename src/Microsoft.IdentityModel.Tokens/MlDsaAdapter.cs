// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Linq;
using System.Security.Cryptography;
using Microsoft.IdentityModel.Logging;

namespace Microsoft.IdentityModel.Tokens;

/// <summary>
/// Provides helper methods for creating <see cref="MLDsa"/> instances from JWK parameters.
/// </summary>
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
                    LogHelper.FormatInvariant(LogMessages.IDX10721, LogHelper.MarkAsNonPII(jsonWebKey.Alg), LogHelper.MarkAsNonPII(nameof(jsonWebKey.Pub)))));

        MLDsaAlgorithm algorithm = GetMLDsaAlgorithm(jsonWebKey.Alg);

        if (usePrivateKey)
        {
            if (string.IsNullOrEmpty(jsonWebKey.Priv))
                throw LogHelper.LogExceptionMessage(
                    new ArgumentException(
                        LogHelper.FormatInvariant(LogMessages.IDX10721, LogHelper.MarkAsNonPII(jsonWebKey.Alg), LogHelper.MarkAsNonPII(nameof(jsonWebKey.Priv)))));

            byte[] seed = Base64UrlEncoder.DecodeBytes(jsonWebKey.Priv);
            MLDsa key = null;
            bool success = false;
            try
            {
                key = MLDsa.ImportMLDsaPrivateSeed(algorithm, seed);

                // Verify the claimed public key matches the key derived from the seed.
                // This prevents key identity confusion where thumbprint/kid is computed
                // from one public key but signing uses a different private key.
                byte[] claimedPub = Base64UrlEncoder.DecodeBytes(jsonWebKey.Pub);
                byte[] derivedPub = key.ExportMLDsaPublicKey();
                if (!claimedPub.SequenceEqual(derivedPub))
                {
                    throw LogHelper.LogExceptionMessage(
                        new ArgumentException(
                            LogHelper.FormatInvariant(
                                LogMessages.IDX10722,
                                LogHelper.MarkAsNonPII(jsonWebKey.Alg))));
                }

                success = true;
                return key;
            }
            finally
            {
                if (!success)
                    key?.Dispose();

                CryptographicOperations.ZeroMemory(seed);
            }
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

    /// <summary>
    /// Creates an independent clone of an <see cref="MLDsa"/> instance by re-importing key material.
    /// The clone is fully independent and safe for concurrent use on a separate thread.
    /// </summary>
    /// <param name="source">The source <see cref="MLDsa"/> to clone.</param>
    /// <param name="includePrivateKey">Whether to include the private key in the clone.</param>
    /// <returns>A new <see cref="MLDsa"/> instance with the same key material.</returns>
    internal static MLDsa CloneMlDsa(MLDsa source, bool includePrivateKey)
    {
        if (source == null)
            throw LogHelper.LogArgumentNullException(nameof(source));

        MLDsaAlgorithm algorithm = source.Algorithm;

        if (includePrivateKey)
        {
            byte[] seed = source.ExportMLDsaPrivateSeed();
            try
            {
                return MLDsa.ImportMLDsaPrivateSeed(algorithm, seed);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(seed);
            }
        }

        byte[] publicKey = source.ExportMLDsaPublicKey();
        return MLDsa.ImportMLDsaPublicKey(algorithm, publicKey);
    }
}
