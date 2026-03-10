// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#nullable enable

using System;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Text;
using Microsoft.IdentityModel.Logging;

namespace Microsoft.IdentityModel.Tokens.Pqc.Composite;

/// <summary>
/// Represents a security key backed by a <see cref="CompositeMLDsa"/> instance
/// that holds both ML-DSA and traditional key components atomically.
/// </summary>
[Experimental("MSIDENT2001")]
public class CompositeMLDsaSecurityKey : AsymmetricSecurityKey
{
    private bool? _hasPrivateKey;
    private int? _keySize;

    /// <summary>
    /// Initializes a new instance of <see cref="CompositeMLDsaSecurityKey"/>
    /// from a <see cref="CompositeMLDsa"/> instance.
    /// </summary>
    /// <param name="compositeMLDsa">The composite ML-DSA key instance.</param>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="compositeMLDsa"/> is null.</exception>
    public CompositeMLDsaSecurityKey(CompositeMLDsa compositeMLDsa)
    {
        CompositeMLDsa = compositeMLDsa ?? throw LogHelper.LogArgumentNullException(nameof(compositeMLDsa));
    }

    /// <summary>
    /// Gets the <see cref="CompositeMLDsa"/> instance backing this key.
    /// </summary>
    public CompositeMLDsa CompositeMLDsa { get; private set; }

    /// <inheritdoc/>
    [Obsolete("HasPrivateKey method is deprecated, please use PrivateKeyStatus instead.")]
    public override bool HasPrivateKey
    {
        get
        {
            if (_hasPrivateKey is null)
                DetectPrivateKey();

            return _hasPrivateKey!.Value;
        }
    }

    /// <inheritdoc/>
    public override PrivateKeyStatus PrivateKeyStatus
    {
        get
        {
            if (_hasPrivateKey is null)
                DetectPrivateKey();

            return _hasPrivateKey!.Value ? PrivateKeyStatus.Exists : PrivateKeyStatus.DoesNotExist;
        }
    }

    /// <inheritdoc/>
    public override int KeySize
    {
        get
        {
            if (_keySize is null)
            {
                byte[] spki = CompositeMLDsa.ExportSubjectPublicKeyInfo();
                _keySize = spki.Length * 8;
                Array.Clear(spki, 0, spki.Length);
            }

            return _keySize.Value;
        }
    }

    /// <inheritdoc/>
    public override bool CanComputeJwkThumbprint() => true;

    /// <inheritdoc/>
    public override byte[] ComputeJwkThumbprint()
    {
        string algorithmName = CompositeMLDsaAlgorithms.GetJoseAlgorithm(CompositeMLDsa.Algorithm);
        byte[] publicKey = CompositeMLDsa.ExportSubjectPublicKeyInfo();

        try
        {
            // Canonical JWK representation per RFC 7638 — alphabetically sorted required members.
            string canonicalJwk = $@"{{""alg"":""{algorithmName}"",""kty"":""{JsonWebAlgorithmsKeyTypes.Akp}"",""pub"":""{Base64UrlEncoder.Encode(publicKey)}""}}";

            using var sha256 = SHA256.Create();

            return sha256.ComputeHash(Encoding.UTF8.GetBytes(canonicalJwk));
        }
        finally
        {
            Array.Clear(publicKey, 0, publicKey.Length);
        }
    }

    private void DetectPrivateKey()
    {
        try
        {
            byte[] pkcs8 = CompositeMLDsa.ExportPkcs8PrivateKey();
            Array.Clear(pkcs8, 0, pkcs8.Length);
            _hasPrivateKey = true;
        }
        catch (CryptographicException)
        {
            _hasPrivateKey = false;
        }
    }
}
