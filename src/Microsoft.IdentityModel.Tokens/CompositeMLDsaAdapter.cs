// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Security.Cryptography;
using Microsoft.IdentityModel.Logging;

#pragma warning disable SYSLIB5006 // CompositeMLDsa is experimental

namespace Microsoft.IdentityModel.Tokens;

/// <summary>
/// Provides helper methods for creating and cloning <see cref="CompositeMLDsa"/> instances from JWK parameters.
/// </summary>
/// <remarks>
/// This adapter implements the key and signature encoding defined in
/// <c>draft-ietf-jose-pq-composite-sigs-01</c>. The composite key and signature
/// are treated as opaque byte sequences; encoding details are handled internally
/// by the .NET <see cref="CompositeMLDsa"/> API.
/// </remarks>
[SuppressMessage("Design", "CA1031:Do not catch general exception types", Justification = "Used as platform test")]
internal static class CompositeMLDsaAdapter
{
    /// <summary>
    /// Creates a <see cref="CompositeMLDsa"/> instance from a <see cref="JsonWebKey"/>.
    /// </summary>
    internal static CompositeMLDsa CreateCompositeMLDsa(JsonWebKey jsonWebKey, bool usePrivateKey)
    {
        if (jsonWebKey == null)
            throw LogHelper.LogArgumentNullException(nameof(jsonWebKey));

        if (string.IsNullOrEmpty(jsonWebKey.Pub))
            throw LogHelper.LogExceptionMessage(
                new ArgumentException(
                    LogHelper.FormatInvariant(
                        LogMessages.IDX10721,
                        LogHelper.MarkAsNonPII(jsonWebKey.Alg),
                        LogHelper.MarkAsNonPII(nameof(jsonWebKey.Pub)))));

        CompositeMLDsaAlgorithm algorithm = GetCompositeMLDsaAlgorithm(jsonWebKey.Alg);

        if (usePrivateKey)
        {
            if (string.IsNullOrEmpty(jsonWebKey.Priv))
                throw LogHelper.LogExceptionMessage(
                    new ArgumentException(
                        LogHelper.FormatInvariant(
                            LogMessages.IDX10721,
                            LogHelper.MarkAsNonPII(jsonWebKey.Alg),
                            LogHelper.MarkAsNonPII(nameof(jsonWebKey.Priv)))));

            byte[] privBytes = Base64UrlEncoder.DecodeBytes(jsonWebKey.Priv);
            CompositeMLDsa key = null;
            bool success = false;
            try
            {
                key = CompositeMLDsa.ImportCompositeMLDsaPrivateKey(algorithm, privBytes);

                // Verify the claimed public key matches the key derived from the private key.
                // This prevents key identity confusion where thumbprint/kid is computed
                // from one public key but signing uses a different private key.
                byte[] claimedPub = Base64UrlEncoder.DecodeBytes(jsonWebKey.Pub);
                byte[] derivedPub = key.ExportCompositeMLDsaPublicKey();
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

                CryptographicOperations.ZeroMemory(privBytes);
            }
        }

        byte[] publicKey = Base64UrlEncoder.DecodeBytes(jsonWebKey.Pub);
        return CompositeMLDsa.ImportCompositeMLDsaPublicKey(algorithm, publicKey);
    }

    /// <summary>
    /// Maps a JOSE algorithm string to the corresponding <see cref="CompositeMLDsaAlgorithm"/>.
    /// </summary>
    internal static CompositeMLDsaAlgorithm GetCompositeMLDsaAlgorithm(string algorithm)
    {
        return algorithm switch
        {
            SecurityAlgorithms.MlDsa44WithECDsaP256 => CompositeMLDsaAlgorithm.MLDsa44WithECDsaP256,
            SecurityAlgorithms.MlDsa65WithECDsaP256 => CompositeMLDsaAlgorithm.MLDsa65WithECDsaP256,
            SecurityAlgorithms.MlDsa87WithECDsaP384 => CompositeMLDsaAlgorithm.MLDsa87WithECDsaP384,
            _ => throw LogHelper.LogArgumentException<ArgumentException>(
                     nameof(algorithm), LogMessages.IDX10652, algorithm)
        };
    }

    /// <summary>
    /// Creates an independent clone of a <see cref="CompositeMLDsa"/> instance by re-importing key material.
    /// Returns <see langword="null"/> if the key is non-exportable (e.g., HSM-backed).
    /// </summary>
    internal static CompositeMLDsa CloneCompositeMLDsa(CompositeMLDsa source, bool includePrivateKey)
    {
        if (source is null)
            throw LogHelper.LogArgumentNullException(nameof(source));

        CompositeMLDsaAlgorithm algorithm = source.Algorithm;

        if (includePrivateKey)
        {
            try
            {
                byte[] privBytes = source.ExportCompositeMLDsaPrivateKey();
                try
                {
                    return CompositeMLDsa.ImportCompositeMLDsaPrivateKey(algorithm, privBytes);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(privBytes);
                }
            }
            catch (CryptographicException)
            {
                // Key is non-exportable — caller must fall back to shared instance with a lock.
                return null;
            }
        }

        try
        {
            byte[] pubBytes = source.ExportCompositeMLDsaPublicKey();
            return CompositeMLDsa.ImportCompositeMLDsaPublicKey(algorithm, pubBytes);
        }
        catch (CryptographicException)
        {
            return null;
        }
    }
}
