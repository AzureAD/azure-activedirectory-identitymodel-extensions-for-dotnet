// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using Microsoft.IdentityModel.Logging;

#pragma warning disable SYSLIB5006 // CompositeMLDsa is experimental

namespace Microsoft.IdentityModel.Tokens;

/// <summary>
/// Represents a Composite ML-DSA security key combining ML-DSA with a traditional algorithm (ECDSA).
/// </summary>
/// <remarks>
/// This type is internal because the JOSE composite spec (draft-ietf-jose-pq-composite-sigs)
/// is pre-RFC and the BCL <see cref="CompositeMLDsa"/> type is [Experimental].
/// It will be promoted to public when both are stable.
/// </remarks>
[SuppressMessage("Design", "CA1031:Do not catch general exception types", Justification = "Used as platform test", Scope = "member")]
internal sealed class CompositeMLDsaSecurityKey : AsymmetricSecurityKey, IDisposable
{
    private bool? _hasPrivateKey;
    private bool _disposed;
    private readonly bool _ownsCompositeMLDsa;

    internal CompositeMLDsaSecurityKey(JsonWebKey webKey, bool usePrivateKey)
        : base(webKey)
    {
        CompositeMLDsa = CompositeMLDsaAdapter.CreateCompositeMLDsa(webKey, usePrivateKey);
        _ownsCompositeMLDsa = true;
        webKey.ConvertedSecurityKey = this;
    }

    internal CompositeMLDsaSecurityKey(CompositeMLDsa compositeMLDsa)
    {
        CompositeMLDsa = compositeMLDsa ?? throw LogHelper.LogArgumentNullException(nameof(compositeMLDsa));
    }

    internal CompositeMLDsa CompositeMLDsa { get; }

    public void Dispose()
    {
        if (!_disposed)
        {
            _disposed = true;
            if (_ownsCompositeMLDsa)
                CompositeMLDsa?.Dispose();
        }
    }

    [Obsolete("HasPrivateKey method is deprecated, please use PrivateKeyStatus instead.")]
    public override bool HasPrivateKey => PrivateKeyStatus == PrivateKeyStatus.Exists;

    public override PrivateKeyStatus PrivateKeyStatus
    {
        get
        {
            if (_hasPrivateKey == null)
            {
                try
                {
                    byte[] dummy = new byte[1];
                    byte[] sig = CompositeMLDsa.SignData(dummy, context: null);
                    CryptographicOperations.ZeroMemory(sig);
                    _hasPrivateKey = true;
                }
                catch (CryptographicException)
                {
                    _hasPrivateKey = false;
                }
                catch (Exception)
                {
                    return PrivateKeyStatus.Unknown;
                }
            }

            return _hasPrivateKey.Value ? PrivateKeyStatus.Exists : PrivateKeyStatus.DoesNotExist;
        }
    }

    /// <summary>
    /// Gets the composite public key size in bits.
    /// </summary>
    public override int KeySize => GetPublicKeySizeInBytes(CompositeMLDsa.Algorithm) * 8;

    public override bool CanComputeJwkThumbprint() => true;

    public override byte[] ComputeJwkThumbprint()
    {
        string algorithmName = GetAlgorithmName(CompositeMLDsa.Algorithm);
        byte[] publicKey = CompositeMLDsa.ExportCompositeMLDsaPublicKey();
        var canonicalJwk = $@"{{""{JsonWebKeyParameterNames.Alg}"":""{algorithmName}"",""{JsonWebKeyParameterNames.Kty}"":""{JsonWebAlgorithmsKeyTypes.Akp}"",""{JsonWebKeyParameterNames.Pub}"":""{Base64UrlEncoder.Encode(publicKey)}""}}";
        return Utility.GenerateSha256Hash(canonicalJwk);
    }

    /// <summary>
    /// Gets the JOSE algorithm name for the specified <see cref="CompositeMLDsaAlgorithm"/>.
    /// </summary>
    internal static string GetAlgorithmName(CompositeMLDsaAlgorithm algorithm)
    {
        if (algorithm == CompositeMLDsaAlgorithm.MLDsa44WithECDsaP256)
            return SecurityAlgorithms.MlDsa44WithECDsaP256;
        if (algorithm == CompositeMLDsaAlgorithm.MLDsa65WithECDsaP256)
            return SecurityAlgorithms.MlDsa65WithECDsaP256;
        if (algorithm == CompositeMLDsaAlgorithm.MLDsa87WithECDsaP384)
            return SecurityAlgorithms.MlDsa87WithECDsaP384;

        throw LogHelper.LogArgumentException<ArgumentException>(nameof(algorithm), LogMessages.IDX10652, algorithm);
    }

    /// <summary>
    /// Returns the composite public key size in bytes for a given <see cref="CompositeMLDsaAlgorithm"/>.
    /// </summary>
    private static int GetPublicKeySizeInBytes(CompositeMLDsaAlgorithm algorithm)
    {
        // ML-DSA pub + EC pub (uncompressed point)
        if (algorithm == CompositeMLDsaAlgorithm.MLDsa44WithECDsaP256) return 1312 + 65;  // 1377
        if (algorithm == CompositeMLDsaAlgorithm.MLDsa65WithECDsaP256) return 1952 + 65;  // 2017
        if (algorithm == CompositeMLDsaAlgorithm.MLDsa87WithECDsaP384) return 2592 + 97;  // 2689

        // Fallback for an unrecognised algorithm — fail explicitly rather than returning an invalid key size.
        throw new CryptographicException(LogHelper.FormatInvariant(LogMessages.IDX10652, LogHelper.MarkAsNonPII(algorithm)));
    }
}
