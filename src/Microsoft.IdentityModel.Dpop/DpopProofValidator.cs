// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Buffers;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Microsoft.IdentityModel.Dpop;

/// <summary>
/// Validates DPoP proof JWTs on the server side per RFC 9449 §4.3.
/// </summary>
/// <remarks>
/// <para>
/// This class is stateless and thread-safe. A single instance may be reused across requests.
/// </para>
/// <para>
/// <strong>Configuring replay protection.</strong> RFC 9449 §4.3 requires servers to prevent DPoP
/// proof replay. IdentityModel surfaces two mechanisms on <see cref="DpopValidationOptions"/> —
/// <see cref="DpopValidationOptions.ExpectedNonce"/> and
/// <see cref="DpopValidationOptions.JtiReplayCache"/>. At least one MUST be configured, OR the
/// caller MUST set <see cref="DpopValidationOptions.ReplayProtectionHandledExternally"/> to
/// <see langword="true"/> to indicate that replay protection is enforced by a higher-layer
/// framework. With neither configured and the flag unset,
/// <see cref="ValidateAsync"/> fails closed with
/// <see cref="DpopValidationFailureType.ReplayProtectionNotConfigured"/>.
/// </para>
/// </remarks>
public partial class DpopProofValidator
{
    private static readonly JsonWebTokenHandler s_tokenHandler = new JsonWebTokenHandler();

    /// <summary>
    /// Validates a DPoP proof JWT from an incoming HTTP request.
    /// </summary>
    /// <param name="dpopProofJwt">The raw DPoP proof JWT from the <c>DPoP</c> request header.</param>
    /// <param name="httpMethod">The HTTP method of the incoming request (e.g., "GET", "POST").</param>
    /// <param name="requestUri">The HTTP URI of the incoming request (absolute).</param>
    /// <param name="accessToken">The access token from the <c>Authorization</c> header, used for <c>ath</c> binding.</param>
    /// <param name="expectedCnfJkt">The expected <c>cnf.jkt</c> thumbprint extracted from the access token, used for key binding.</param>
    /// <param name="options">Validation options controlling algorithms, lifetime, nonce, and replay detection.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>A <see cref="DpopValidationResult"/> with the validation outcome and JWK thumbprint.</returns>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="dpopProofJwt"/>, <paramref name="httpMethod"/>,
    /// <paramref name="requestUri"/>, <paramref name="accessToken"/>,
    /// <paramref name="expectedCnfJkt"/>, or <paramref name="options"/> is null.
    /// </exception>
    /// <exception cref="ArgumentException">
    /// Thrown when <paramref name="requestUri"/> is not an absolute URI.
    /// </exception>
    public virtual async Task<DpopValidationResult> ValidateAsync(
        string dpopProofJwt,
        string httpMethod,
        Uri requestUri,
        string accessToken,
        string expectedCnfJkt,
        DpopValidationOptions options,
        CancellationToken cancellationToken = default)
    {
        return ToPublicResult(
            await ValidateInternalAsync(
                dpopProofJwt,
                httpMethod,
                requestUri,
                accessToken,
                expectedCnfJkt,
                options,
                cancellationToken).ConfigureAwait(false));
    }

    /// <summary>
    /// Computes the <c>ath</c> (access token hash) per RFC 9449 §4.2:
    /// base64url-encoded SHA-256 hash of the ASCII-encoded access token.
    /// </summary>
    /// <param name="accessToken">The raw access token string.</param>
    /// <returns>The base64url-encoded SHA-256 hash.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="accessToken"/> is null.</exception>
    internal static string ComputeAccessTokenHash(string accessToken)
    {
        _ = accessToken ?? throw new ArgumentNullException(nameof(accessToken));

#if NET6_0_OR_GREATER
        // Typical access tokens (1-2 KB) hash without any heap allocation on the input side;
        // larger tokens fall through to the heap path below. 1 KB cap keeps the stack budget
        // safe for use under deep ASP.NET pipelines.
        const int StackAllocThreshold = 1024;
        int maxBytes = Encoding.UTF8.GetMaxByteCount(accessToken.Length);
        if (maxBytes <= StackAllocThreshold)
        {
            Span<byte> tokenSpan = stackalloc byte[StackAllocThreshold];
            int written = Encoding.UTF8.GetBytes(accessToken, tokenSpan);
            Span<byte> hashSpan = stackalloc byte[32];
            SHA256.HashData(tokenSpan.Slice(0, written), hashSpan);
            return Base64UrlEncoder.Encode(hashSpan.ToArray());
        }
#endif

        var tokenBytes = Encoding.UTF8.GetBytes(accessToken);
#if NET6_0_OR_GREATER
        var hash = SHA256.HashData(tokenBytes);
#else
        byte[] hash;
        using (var sha256 = SHA256.Create())
        {
            hash = sha256.ComputeHash(tokenBytes);
        }
#endif
        return Base64UrlEncoder.Encode(hash);
    }

    /// <summary>
    /// Checks whether a <see cref="JsonWebKey"/> contains private key material.
    /// Per RFC 9449 §4.3 step 7, the DPoP proof's JWK must be a public key only.
    /// </summary>
    /// <param name="jwk">The JSON Web Key to check.</param>
    /// <returns><see langword="true"/> if private key parameters are present; otherwise <see langword="false"/>.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="jwk"/> is null.</exception>
    internal static bool ContainsPrivateKeyMaterial(JsonWebKey jwk)
    {
        _ = jwk ?? throw new ArgumentNullException(nameof(jwk));

        // RSA private parameters: d, p, q, dp, dq, qi
        // EC private parameter: d (shared check with RSA)
        return !string.IsNullOrEmpty(jwk.D) ||
               !string.IsNullOrEmpty(jwk.P) ||
               !string.IsNullOrEmpty(jwk.Q) ||
               !string.IsNullOrEmpty(jwk.DP) ||
               !string.IsNullOrEmpty(jwk.DQ) ||
               !string.IsNullOrEmpty(jwk.QI);
    }

    /// <summary>
    /// Converts a <see cref="JsonWebKey"/> to an asymmetric <see cref="SecurityKey"/> from its
    /// public key parameters (n/e for RSA, crv/x/y for EC).
    /// </summary>
    internal static bool TryConvertToAsymmetricKeyFromBareParameters(JsonWebKey jwk, out SecurityKey key)
    {
        _ = jwk ?? throw new ArgumentNullException(nameof(jwk));

        key = null;

        if (JsonWebAlgorithmsKeyTypes.RSA.Equals(jwk.Kty))
        {
            return JsonWebKeyConverter.TryCreateToRsaSecurityKey(jwk, out key);
        }
        else if (JsonWebAlgorithmsKeyTypes.EllipticCurve.Equals(jwk.Kty))
        {
            return JsonWebKeyConverter.TryConvertToECDsaSecurityKey(jwk, out key);
        }

        return false;
    }

    /// <summary>
    /// Verifies the DPoP proof signature using a pooled buffer for the signing input.
    /// </summary>
    private static bool VerifyProofSignature(JsonWebToken proofToken, SignatureProvider signatureProvider)
    {
        string encodedToken = proofToken.EncodedToken;
        string encodedSignature = proofToken.EncodedSignature;
        // JWS signing input is "header.payload"; subtract the signature length plus 1 for the '.' separator that precedes it.
        int signingInputLength = encodedToken.Length - encodedSignature.Length - 1;
        if (signingInputLength <= 0)
        {
            // Defensive: JsonWebToken parsing should already guarantee header.payload.signature shape,
            // but bail out before Rent(negative) would throw if a malformed token ever reached us.
            return false;
        }

        byte[] messageBuffer = ArrayPool<byte>.Shared.Rent(signingInputLength);
        try
        {
            Encoding.ASCII.GetBytes(encodedToken, 0, signingInputLength, messageBuffer, 0);
            byte[] signatureBytes = Base64UrlEncoder.DecodeBytes(encodedSignature);
            return signatureProvider.Verify(messageBuffer, 0, signingInputLength, signatureBytes, 0, signatureBytes.Length);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(messageBuffer);
        }
    }

    /// <summary>
    /// Constant-time UTF-8 comparison of two strings. On TFMs that support span-based encoding the
    /// UTF-8 bytes are produced into stack-allocated buffers so the hot comparison paths
    /// (ath, nonce, cnf.jkt) avoid heap allocations entirely. Larger inputs and older TFMs fall back
    /// to the allocating <see cref="Utility.AreEqual(byte[], byte[])"/> helper.
    /// </summary>
    private static bool AreEqualUtf8(string a, string b)
    {
        if (a == null || b == null)
        {
            return false;
        }

#if NET6_0_OR_GREATER
        // 256 bytes covers ath (~43), nonce (typically ≤ 128), and cnf.jkt (~43) with headroom.
        const int StackAllocThreshold = 256;
        int maxBytesA = Encoding.UTF8.GetMaxByteCount(a.Length);
        int maxBytesB = Encoding.UTF8.GetMaxByteCount(b.Length);
        if (maxBytesA <= StackAllocThreshold && maxBytesB <= StackAllocThreshold)
        {
            Span<byte> bufA = stackalloc byte[StackAllocThreshold];
            Span<byte> bufB = stackalloc byte[StackAllocThreshold];
            int lenA = Encoding.UTF8.GetBytes(a, bufA);
            int lenB = Encoding.UTF8.GetBytes(b, bufB);
            return System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(bufA.Slice(0, lenA), bufB.Slice(0, lenB));
        }
#endif
        return Utility.AreEqual(Encoding.UTF8.GetBytes(a), Encoding.UTF8.GetBytes(b));
    }

    /// <summary>
    /// Validates that the JWK is acceptable for the given algorithm — kty/alg/crv consistency
    /// plus configured RSA modulus bounds. Returns a human-readable reason on rejection, or null on success.
    /// </summary>
    private static string ValidateJwkForAlgorithm(string alg, JsonWebKey jwk, DpopValidationOptions options)
    {
        if (jwk.Kty != JsonWebAlgorithmsKeyTypes.RSA && jwk.Kty != JsonWebAlgorithmsKeyTypes.EllipticCurve)
            return $"DPoP proof JWK 'kty' '{jwk.Kty}' is not supported; expected 'RSA' or 'EC'.";

        if (!jwk.IsSupportedAlgorithm(alg))
            return $"DPoP proof algorithm '{alg}' is not supported by the JWK (kty '{jwk.Kty}').";

        if (jwk.Kty == JsonWebAlgorithmsKeyTypes.RSA)
        {
            if (jwk.N == null)
                return "DPoP proof RSA JWK is missing the 'n' parameter.";

            // Bound the RSA modulus size without decoding base64url. Each base64url character carries
            // 6 bits of payload, so N.Length * 6 is an upper bound on the encoded modulus bit length
            // (the true value is within 8 bits of this ceiling because the final base64url char may
            // contribute fewer than 6 significant bits and the decoded byte string can include a leading
            // 0x00). We add 8 to the maximum to avoid rejecting keys at the boundary, and compare the
            // ceiling directly to the minimum so we only reject when even the most generous interpretation
            // is below the floor. Runs before key import to bound DoS cost on client-controlled keys.
            int encodedBitCeiling = jwk.N.Length * 6;
            if (encodedBitCeiling > options.MaxRsaKeySizeInBits + 8)
                return "DPoP proof RSA key exceeds the maximum allowed size.";

            if (encodedBitCeiling < options.MinRsaKeySizeInBits)
                return "DPoP proof RSA key is below the minimum allowed size.";

            return null;
        }

        // EC: pin curve to alg.
        string expectedCrv = alg switch
        {
            SecurityAlgorithms.EcdsaSha256 or SecurityAlgorithms.EcdsaSha256Signature => JsonWebKeyECTypes.P256,
            SecurityAlgorithms.EcdsaSha384 or SecurityAlgorithms.EcdsaSha384Signature => JsonWebKeyECTypes.P384,
            SecurityAlgorithms.EcdsaSha512 or SecurityAlgorithms.EcdsaSha512Signature => JsonWebKeyECTypes.P521,
            _ => null,
        };

        if (expectedCrv == null)
            return $"DPoP proof algorithm '{alg}' has no curve binding defined for EC keys.";

        bool crvMatches = jwk.Crv == expectedCrv
            || (expectedCrv == JsonWebKeyECTypes.P521 && jwk.Crv == JsonWebKeyECTypes.P512);

        if (!crvMatches)
            return $"DPoP proof algorithm '{alg}' requires curve '{expectedCrv}' but JWK 'crv' is '{jwk.Crv}'.";

        return null;
    }

    /// <summary>
    /// Computes the base64url-encoded SHA-256 JWK thumbprint per RFC 7638.
    /// </summary>
    /// <param name="jwk">The JSON Web Key.</param>
    /// <returns>The base64url-encoded thumbprint.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="jwk"/> is null.</exception>
    internal static string ComputeJwkThumbprint(JsonWebKey jwk)
    {
        _ = jwk ?? throw new ArgumentNullException(nameof(jwk));

        var thumbprintBytes = jwk.ComputeJwkThumbprint();
        return Base64UrlEncoder.Encode(thumbprintBytes);
    }
}
