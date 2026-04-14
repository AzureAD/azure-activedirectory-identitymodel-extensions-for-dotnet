// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
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
/// This class is stateless and thread-safe. A single instance may be reused across requests.
/// </remarks>
public class DPoPProofValidator
{
    /// <summary>
    /// Validates a DPoP proof JWT from an incoming HTTP request.
    /// </summary>
    /// <param name="dpopProofJwt">The raw DPoP proof JWT from the <c>DPoP</c> request header.</param>
    /// <param name="httpMethod">The HTTP method of the incoming request (e.g., "GET", "POST").</param>
    /// <param name="requestUri">The HTTP URI of the incoming request (absolute).</param>
    /// <param name="accessToken">
    /// The access token from the <c>Authorization</c> header, used for <c>ath</c> binding.
    /// Pass null when validating a DPoP proof for a token request (no access token yet).
    /// </param>
    /// <param name="options">Validation options controlling algorithms, lifetime, nonce, and replay detection.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>A <see cref="DPoPValidationResult"/> with the validation outcome and JWK thumbprint.</returns>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="dpopProofJwt"/>, <paramref name="httpMethod"/>,
    /// <paramref name="requestUri"/>, or <paramref name="options"/> is null.
    /// </exception>
    /// <exception cref="ArgumentException">
    /// Thrown when <paramref name="requestUri"/> is not an absolute URI.
    /// </exception>
    public virtual async Task<DPoPValidationResult> ValidateAsync(
        string dpopProofJwt,
        string httpMethod,
        Uri requestUri,
        string accessToken,
        DPoPValidationOptions options,
        CancellationToken cancellationToken = default)
    {
        _ = dpopProofJwt ?? throw new ArgumentNullException(nameof(dpopProofJwt));
        _ = httpMethod ?? throw new ArgumentNullException(nameof(httpMethod));
        _ = requestUri ?? throw new ArgumentNullException(nameof(requestUri));
        _ = options ?? throw new ArgumentNullException(nameof(options));

        if (string.IsNullOrWhiteSpace(dpopProofJwt))
            return DPoPValidationResult.Failed("DPoP proof is empty.", DPoPErrorCodes.InvalidDPoPProof);

        if (!requestUri.IsAbsoluteUri)
            throw new ArgumentException("URI must be absolute.", nameof(requestUri));

        cancellationToken.ThrowIfCancellationRequested();

        try
        {
            return await ValidateCoreAsync(dpopProofJwt, httpMethod, requestUri, accessToken, options, cancellationToken)
                .ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return DPoPValidationResult.Failed(
                $"DPoP proof validation error: {ex.Message}",
                DPoPErrorCodes.InvalidDPoPProof);
        }
    }

    /// <summary>
    /// Validates that the <c>cnf.jkt</c> claim in an access token matches the DPoP proof's
    /// public key thumbprint, using constant-time comparison to prevent timing attacks.
    /// </summary>
    /// <param name="accessTokenCnfJkt">The <c>jkt</c> value from the access token's <c>cnf</c> claim.</param>
    /// <param name="dpopProofJwkThumbprint">The computed JWK SHA-256 thumbprint from the DPoP proof.</param>
    /// <returns><see langword="true"/> if the values match; otherwise <see langword="false"/>.</returns>
    public static bool ValidateCnfJktBinding(string accessTokenCnfJkt, string dpopProofJwkThumbprint)
    {
        if (string.IsNullOrEmpty(accessTokenCnfJkt) || string.IsNullOrEmpty(dpopProofJwkThumbprint))
            return false;

        return Utility.AreEqual(
            Encoding.UTF8.GetBytes(accessTokenCnfJkt),
            Encoding.UTF8.GetBytes(dpopProofJwkThumbprint));
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

        // Use strict ASCII encoding per RFC 9449 §4.2 — reject non-ASCII tokens
        // rather than silently replacing with '?' (which would produce an incorrect hash).
        var tokenBytes = Encoding.GetEncoding(
            "us-ascii",
            EncoderFallback.ExceptionFallback,
            DecoderFallback.ExceptionFallback).GetBytes(accessToken);
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

    private static async Task<DPoPValidationResult> ValidateCoreAsync(
        string dpopProofJwt,
        string httpMethod,
        Uri requestUri,
        string accessToken,
        DPoPValidationOptions options,
        CancellationToken cancellationToken)
    {
        var handler = new JsonWebTokenHandler();
        var proofToken = handler.ReadJsonWebToken(dpopProofJwt);

        // Validate typ == dpop+jwt
        if (!string.Equals(proofToken.Typ, DPoPConstants.DPoPProofTokenType, StringComparison.OrdinalIgnoreCase))
        {
            return DPoPValidationResult.Failed(
                "DPoP proof typ must be 'dpop+jwt'.",
                DPoPErrorCodes.InvalidDPoPProof);
        }

        // Validate alg is asymmetric and in allowed set
        var alg = proofToken.Alg;
        if (string.IsNullOrEmpty(alg) ||
            string.Equals(alg, "none", StringComparison.OrdinalIgnoreCase))
        {
            return DPoPValidationResult.Failed(
                "DPoP proof algorithm must not be 'none'.",
                DPoPErrorCodes.InvalidDPoPProof);
        }

        if (alg.StartsWith("HS", StringComparison.OrdinalIgnoreCase))
        {
            return DPoPValidationResult.Failed(
                "DPoP proof must use an asymmetric algorithm.",
                DPoPErrorCodes.InvalidDPoPProof);
        }

        if (options.AllowedSigningAlgorithms.Count > 0 &&
            !options.AllowedSigningAlgorithms.Contains(alg))
        {
            return DPoPValidationResult.Failed(
                $"DPoP proof algorithm '{alg}' is not in the allowed set.",
                DPoPErrorCodes.InvalidDPoPProof);
        }

        // Extract JWK from header, verify no private key present
        if (!proofToken.TryGetHeaderValue("jwk", out object jwkObj) || jwkObj == null)
        {
            return DPoPValidationResult.Failed(
                "DPoP proof is missing the 'jwk' header parameter.",
                DPoPErrorCodes.InvalidDPoPProof);
        }

        JsonWebKey jwk;
        try
        {
            jwk = new JsonWebKey(jwkObj.ToString());
        }
        catch (Exception ex)
        {
            return DPoPValidationResult.Failed(
                $"DPoP proof contains an invalid 'jwk' header: {ex.Message}",
                DPoPErrorCodes.InvalidDPoPProof);
        }

        if (ContainsPrivateKeyMaterial(jwk))
        {
            return DPoPValidationResult.Failed(
                "DPoP proof JWK must not contain private key material.",
                DPoPErrorCodes.InvalidDPoPProof);
        }

        // Validate signature using extracted JWK
        var validationParams = new TokenValidationParameters
        {
            ValidateIssuer = false,
            ValidateAudience = false,
            ValidateLifetime = false,
            IssuerSigningKey = jwk,
            ValidAlgorithms = new string[] { alg },
        };

        var signatureResult = await handler
            .ValidateTokenAsync(proofToken, validationParams, cancellationToken)
            .ConfigureAwait(false);

        if (!signatureResult.IsValid)
        {
            return DPoPValidationResult.Failed(
                "DPoP proof signature validation failed.",
                DPoPErrorCodes.InvalidDPoPProof);
        }

        // Validate htm matches HTTP method
        if (!proofToken.TryGetPayloadValue(DPoPClaimTypes.Htm, out string htmValue) ||
            !string.Equals(httpMethod, htmValue, StringComparison.OrdinalIgnoreCase))
        {
            return DPoPValidationResult.Failed(
                "DPoP proof 'htm' claim does not match the HTTP method.",
                DPoPErrorCodes.InvalidDPoPProof);
        }

        // Validate htu matches request URI
        // Per RFC 9449 §4.3: compare scheme + authority + path (no query/fragment)
        if (!proofToken.TryGetPayloadValue(DPoPClaimTypes.Htu, out string htuValue))
        {
            return DPoPValidationResult.Failed(
                "DPoP proof is missing the 'htu' claim.",
                DPoPErrorCodes.InvalidDPoPProof);
        }

        var normalizedRequestUri = requestUri.GetLeftPart(UriPartial.Path);
        if (!string.Equals(normalizedRequestUri, htuValue, StringComparison.OrdinalIgnoreCase))
        {
            return DPoPValidationResult.Failed(
                "DPoP proof 'htu' claim does not match the request URI.",
                DPoPErrorCodes.InvalidDPoPProof);
        }

        // Validate iat freshness
        if (!proofToken.TryGetPayloadValue(DPoPClaimTypes.Iat, out long iat))
        {
            return DPoPValidationResult.Failed(
                "DPoP proof is missing the 'iat' claim.",
                DPoPErrorCodes.InvalidDPoPProof);
        }

        var issuedAt = DateTimeOffset.FromUnixTimeSeconds(iat);
#if NET8_0_OR_GREATER
        var now = options.TimeProvider.GetUtcNow();
#else
        var now = DateTimeOffset.UtcNow;
#endif
        var maxAge = TimeSpan.FromSeconds(options.MaxLifetimeInSeconds + options.ClockSkewInSeconds);

        if (now - issuedAt > maxAge)
        {
            return DPoPValidationResult.Failed(
                "DPoP proof has expired.",
                DPoPErrorCodes.InvalidDPoPProof);
        }

        // Reject proofs issued in the future beyond clock skew
        if (issuedAt - now > TimeSpan.FromSeconds(options.ClockSkewInSeconds))
        {
            return DPoPValidationResult.Failed(
                "DPoP proof 'iat' is too far in the future.",
                DPoPErrorCodes.InvalidDPoPProof);
        }

        // Validate jti present
        // The jti claim is always required per RFC 9449 §4.2, regardless of whether
        // jti-based replay detection is enabled.
        if (!proofToken.TryGetPayloadValue(DPoPClaimTypes.Jti, out string jtiValue) ||
            string.IsNullOrEmpty(jtiValue))
        {
            return DPoPValidationResult.Failed(
                "DPoP proof is missing the 'jti' claim.",
                DPoPErrorCodes.InvalidDPoPProof);
        }

        // Replay protection
        if (options.JtiReplayCache != null)
        {
            var jtiExpiration = issuedAt.Add(maxAge);
            bool added = await options.JtiReplayCache
                .TryAddAsync(jtiValue, jtiExpiration, cancellationToken)
                .ConfigureAwait(false);

            if (!added)
            {
                return DPoPValidationResult.Failed(
                    "DPoP proof 'jti' has already been used (replay detected).",
                    DPoPErrorCodes.InvalidDPoPProof);
            }
        }

        // Validate nonce if expected
        if (options.ExpectedNonce != null)
        {
            if (!proofToken.TryGetPayloadValue(DPoPClaimTypes.Nonce, out string nonceValue) ||
                string.IsNullOrEmpty(nonceValue))
            {
                return DPoPValidationResult.NonceRequired();
            }

            if (!string.Equals(options.ExpectedNonce, nonceValue, StringComparison.Ordinal))
            {
                return DPoPValidationResult.NonceRequired();
            }
        }

        // Validate ath (access token hash)
        if (!string.IsNullOrEmpty(accessToken) && options.RequireAccessTokenHash)
        {
            if (!proofToken.TryGetPayloadValue(DPoPClaimTypes.Ath, out string athValue) ||
                string.IsNullOrEmpty(athValue))
            {
                return DPoPValidationResult.Failed(
                    "DPoP proof is missing the 'ath' claim.",
                    DPoPErrorCodes.InvalidDPoPProof);
            }

            var expectedAth = ComputeAccessTokenHash(accessToken);
            if (!string.Equals(athValue, expectedAth, StringComparison.Ordinal))
            {
                return DPoPValidationResult.Failed(
                    "DPoP proof 'ath' claim does not match the access token hash.",
                    DPoPErrorCodes.InvalidDPoPProof);
            }
        }

        // Compute thumbprint and return success
        var thumbprint = ComputeJwkThumbprint(jwk);
        return DPoPValidationResult.Success(thumbprint, jwk);
    }
}
