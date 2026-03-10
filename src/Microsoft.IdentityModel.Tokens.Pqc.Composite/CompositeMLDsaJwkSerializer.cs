// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#nullable enable

using System;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using Microsoft.IdentityModel.Logging;

namespace Microsoft.IdentityModel.Tokens.Pqc.Composite;

/// <summary>
/// Serializes and deserializes <see cref="CompositeMLDsaSecurityKey"/> instances
/// to and from <see cref="JsonWebKey"/> objects using the JOSE AKP key type.
/// </summary>
/// <remarks>
/// JWK format per draft-ietf-jose-pq-composite-sigs-01:
/// <list type="bullet">
///   <item><c>kty</c>: "AKP"</item>
///   <item><c>alg</c>: JOSE algorithm identifier</item>
///   <item><c>pub</c>: SPKI-encoded public key (base64url)</item>
///   <item><c>priv</c>: PKCS#8-encoded private key (base64url, optional)</item>
/// </list>
/// </remarks>
[Experimental("MSIDENT2001")]
public static class CompositeMLDsaJwkSerializer
{
    /// <summary>
    /// Creates a <see cref="JsonWebKey"/> from a <see cref="CompositeMLDsaSecurityKey"/>.
    /// </summary>
    /// <param name="key">The composite ML-DSA security key to convert.</param>
    /// <returns>A <see cref="JsonWebKey"/> representing the key.</returns>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="key"/> is null.</exception>
    public static JsonWebKey ToJsonWebKey(CompositeMLDsaSecurityKey key)
    {
        if (key is null)
            throw LogHelper.LogArgumentNullException(nameof(key));

        string joseAlg = CompositeMLDsaAlgorithms.GetJoseAlgorithm(key.CompositeMLDsa.Algorithm);
        byte[] spki = key.CompositeMLDsa.ExportSubjectPublicKeyInfo();

        var jwk = new JsonWebKey
        {
            Kty = JsonWebAlgorithmsKeyTypes.Akp,
            Alg = joseAlg,
            Pub = Base64UrlEncoder.Encode(spki),
        };

        if (key.PrivateKeyStatus == PrivateKeyStatus.Exists)
        {
            byte[] pkcs8 = key.CompositeMLDsa.ExportPkcs8PrivateKey();
            jwk.Priv = Base64UrlEncoder.Encode(pkcs8);
            Array.Clear(pkcs8, 0, pkcs8.Length);
        }

        if (!string.IsNullOrEmpty(key.KeyId))
            jwk.Kid = key.KeyId;

        return jwk;
    }

    /// <summary>
    /// Creates a <see cref="CompositeMLDsaSecurityKey"/> from a <see cref="JsonWebKey"/>.
    /// </summary>
    /// <param name="jwk">The JWK to convert.</param>
    /// <returns>A <see cref="CompositeMLDsaSecurityKey"/> representing the key.</returns>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="jwk"/> is null.</exception>
    /// <exception cref="ArgumentException">
    /// Thrown if the JWK <c>kty</c> is not "AKP" or required fields are missing.
    /// </exception>
    public static CompositeMLDsaSecurityKey FromJsonWebKey(JsonWebKey jwk)
    {
        if (jwk is null)
            throw LogHelper.LogArgumentNullException(nameof(jwk));

        if (!string.Equals(jwk.Kty, JsonWebAlgorithmsKeyTypes.Akp, StringComparison.Ordinal))
            throw new ArgumentException(
                $"Expected kty '{JsonWebAlgorithmsKeyTypes.Akp}' but got '{jwk.Kty}'.");

        CompositeMLDsa compositeMLDsa;

        if (!string.IsNullOrEmpty(jwk.Priv))
        {
            byte[] pkcs8 = Base64UrlEncoder.DecodeBytes(jwk.Priv);
            compositeMLDsa = CompositeMLDsa.ImportPkcs8PrivateKey(pkcs8);
            Array.Clear(pkcs8, 0, pkcs8.Length);
        }
        else if (!string.IsNullOrEmpty(jwk.Pub))
        {
            byte[] spki = Base64UrlEncoder.DecodeBytes(jwk.Pub);
            compositeMLDsa = CompositeMLDsa.ImportSubjectPublicKeyInfo(spki);
        }
        else
        {
            throw new ArgumentException("JWK must contain either 'pub' or 'priv' field.");
        }

        var key = new CompositeMLDsaSecurityKey(compositeMLDsa);

        if (!string.IsNullOrEmpty(jwk.Kid))
            key.KeyId = jwk.Kid;

        return key;
    }
}
