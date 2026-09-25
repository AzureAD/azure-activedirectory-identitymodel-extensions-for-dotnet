// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Buffers;
using System.Collections.Generic;
using System.Runtime.ExceptionServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Dpop.Experimental;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Tokens.Experimental;

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
public class DpopProofValidator
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

#nullable enable
    private const string SignatureProviderReleaseExceptionKey =
        "Microsoft.IdentityModel.Dpop.SignatureProviderReleaseException";

    private static readonly DpopPassThroughValidators s_passThroughValidators = new();
    private static readonly ISignatureValidator s_dpopSignatureValidator =
        new DpopSignatureValidator();

    internal async Task<ValidationResult<ValidatedDpopProof, ValidationError>> ValidateInternalAsync(
        string dpopProofJwt,
        string httpMethod,
        Uri requestUri,
        string accessToken,
        string expectedCnfJkt,
        DpopValidationOptions options,
        CancellationToken cancellationToken = default)
    {
        _ = dpopProofJwt ?? throw new ArgumentNullException(nameof(dpopProofJwt));
        _ = httpMethod ?? throw new ArgumentNullException(nameof(httpMethod));
        _ = requestUri ?? throw new ArgumentNullException(nameof(requestUri));
        _ = accessToken ?? throw new ArgumentNullException(nameof(accessToken));
        _ = expectedCnfJkt ?? throw new ArgumentNullException(nameof(expectedCnfJkt));
        _ = options ?? throw new ArgumentNullException(nameof(options));

        if (string.IsNullOrWhiteSpace(dpopProofJwt))
            return new DpopProofValidationError("DPoP proof is empty.", DpopValidationFailureType.ProofMissing);

        if (dpopProofJwt.Length > options.MaxProofTokenSizeInBytes)
            return new DpopProofValidationError("DPoP proof exceeds the maximum allowed size.", DpopValidationFailureType.ProofExceedsMaxSize);

        if (string.IsNullOrWhiteSpace(accessToken))
            return new DpopProofValidationError("Access token is empty.", DpopValidationFailureType.AccessTokenMissing);

        if (string.IsNullOrWhiteSpace(expectedCnfJkt))
            return new DpopProofValidationError("Expected cnf.jkt is empty.", DpopValidationFailureType.CnfJktMissing);

        if (!requestUri.IsAbsoluteUri)
            throw new ArgumentException("URI must be absolute.", nameof(requestUri));

        if (options.ExpectedNonce == null
            && options.JtiReplayCache == null
            && !options.ReplayProtectionHandledExternally)
        {
            return new DpopProofValidationError(
                "DPoP replay protection is not configured. Set DpopValidationOptions.ExpectedNonce or "
                + "DpopValidationOptions.JtiReplayCache, or set DpopValidationOptions.ReplayProtectionHandledExternally "
                + "to true if replay protection is enforced by a higher-layer framework.",
                DpopValidationFailureType.ReplayProtectionNotConfigured);
        }

        cancellationToken.ThrowIfCancellationRequested();

        try
        {
            JsonWebToken proofToken;
            try
            {
                proofToken = s_tokenHandler.ReadJsonWebToken(dpopProofJwt);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                return new DpopProofValidationError(
                    "DPoP proof validation failed.",
                    DpopValidationFailureType.UnexpectedError,
                    ValidationFailureType.TokenReadingFailed,
                    ex);
            }

            if (!string.Equals(proofToken.Typ, DpopConstants.DpopProofTokenType, StringComparison.OrdinalIgnoreCase))
            {
                return new DpopProofValidationError(
                    "DPoP proof typ must be 'dpop+jwt'.",
                    DpopValidationFailureType.TokenTypeInvalid);
            }

            string alg = proofToken.Alg;
            if (string.IsNullOrEmpty(alg))
            {
                return new DpopProofValidationError(
                    "DPoP proof algorithm must not be empty.",
                    DpopValidationFailureType.AlgorithmDisallowed);
            }

            if (string.Equals(alg, "none", StringComparison.OrdinalIgnoreCase))
            {
                return new DpopProofValidationError(
                    "DPoP proof algorithm must not be 'none'.",
                    DpopValidationFailureType.AlgorithmDisallowed);
            }

            if (SupportedAlgorithms.IsSupportedSymmetricAlgorithm(alg))
            {
                return new DpopProofValidationError(
                    "DPoP proof must use an asymmetric algorithm.",
                    DpopValidationFailureType.AlgorithmDisallowed);
            }

            if (options.AllowedSigningAlgorithms == null || options.AllowedSigningAlgorithms.Count <= 0)
            {
                return new DpopProofValidationError(
                    "The allowed algorithm set cannot be null or empty.",
                    DpopValidationFailureType.InvalidConfiguration);
            }

            if (!options.AllowedSigningAlgorithms.Contains(alg))
            {
                return new DpopProofValidationError(
                    $"DPoP proof algorithm '{alg}' is not in the allowed set.",
                    DpopValidationFailureType.AlgorithmDisallowed);
            }

            if (!proofToken.TryGetHeaderValue("jwk", out object? jwkObj) || jwkObj == null)
            {
                return new DpopProofClaimValidationError(
                    "jwk",
                    "DPoP proof is missing the 'jwk' header parameter.",
                    DpopValidationFailureType.JwkMissing);
            }

            JsonWebKey jwk;
            try
            {
                jwk = new JsonWebKey(jwkObj.ToString());
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                return new DpopProofClaimValidationError(
                    "jwk",
                    "DPoP proof contains an invalid 'jwk' header.",
                    DpopValidationFailureType.ProofParseFailure,
                    ex);
            }

            if (ContainsPrivateKeyMaterial(jwk))
            {
                return new DpopProofClaimValidationError(
                    "jwk",
                    "DPoP proof JWK must not contain private key material.",
                    DpopValidationFailureType.JwkInvalid);
            }

            string? jwkRejectReason = ValidateJwkForAlgorithm(alg, jwk, options);
            if (jwkRejectReason != null)
            {
                return new DpopProofClaimValidationError(
                    "jwk",
                    jwkRejectReason,
                    DpopValidationFailureType.JwkInvalid);
            }

            if (!TryConvertToAsymmetricKeyFromBareParameters(jwk, out SecurityKey signingKey))
            {
                return new DpopProofClaimValidationError(
                    "jwk",
                    "DPoP proof JWK could not be converted to a supported asymmetric key.",
                    DpopValidationFailureType.JwkInvalid);
            }

            var validationParameters = new ValidationParameters
            {
                AudienceValidator = s_passThroughValidators,
                IssuerValidatorAsync = s_passThroughValidators,
                LifetimeValidator = s_passThroughValidators,
                SignatureValidator = s_dpopSignatureValidator,
            };

            validationParameters.SigningKeys.Add(signingKey);
            validationParameters.ValidAlgorithms.Add(alg);

            // Never let the result-based handler enter ValidateJWEAsync. Preserve the current
            // signature-validation outcome for five-part tokens that pass typ/alg/JWK checks.
            var callContext = new CallContext();
            if (proofToken.IsEncrypted)
            {
                ValidationResult<SecurityKey, ValidationError> encryptedSignatureResult;
                try
                {
                    encryptedSignatureResult = s_dpopSignatureValidator.ValidateSignature(
                        proofToken,
                        validationParameters,
                        configuration: null,
                        callContext);
                }
                catch (Exception ex)
                {
                    encryptedSignatureResult = new SignatureValidationError(
                        new MessageDetail("DPoP proof signature validation failed."),
                        SignatureValidationFailure.ValidatorThrew,
                        ValidationError.GetCurrentStackFrame(),
                        ex);
                }

                if (ConsumeSignatureProviderReleaseException(callContext) is ValidationError releaseError)
                    return releaseError;

                if (!encryptedSignatureResult.Succeeded)
                    return encryptedSignatureResult.Error!;
            }
            else
            {
                IResultBasedValidation handler = s_tokenHandler;

                ValidationResult<ValidatedToken, ValidationError> tokenResult =
                    await handler.ValidateTokenAsync(
                        proofToken,
                        validationParameters,
                        callContext,
                        cancellationToken).ConfigureAwait(false);

                if (ConsumeSignatureProviderReleaseException(callContext) is ValidationError releaseError)
                    return releaseError;

                if (!tokenResult.Succeeded)
                    return tokenResult.Error!;
            }

            if (!proofToken.TryGetPayloadValue(DpopClaimTypes.Htm, out string htmValue) || string.IsNullOrWhiteSpace(htmValue))
            {
                return new DpopProofClaimValidationError(
                    DpopClaimTypes.Htm,
                    "DPoP proof is missing the 'htm' claim.",
                    DpopValidationFailureType.HtmMissing);
            }

            if (!string.Equals(httpMethod, htmValue, StringComparison.OrdinalIgnoreCase))
            {
                return new DpopProofClaimValidationError(
                    DpopClaimTypes.Htm,
                    "DPoP proof 'htm' claim does not match the HTTP method.",
                    DpopValidationFailureType.HtmMismatch);
            }

            if (!proofToken.TryGetPayloadValue(DpopClaimTypes.Htu, out string htuValue) || string.IsNullOrWhiteSpace(htuValue))
            {
                return new DpopProofClaimValidationError(
                    DpopClaimTypes.Htu,
                    "DPoP proof is missing the 'htu' claim.",
                    DpopValidationFailureType.HtuMissing);
            }

            if (!UriComparer.AreEquivalent(requestUri, htuValue))
            {
                return new DpopProofClaimValidationError(
                    DpopClaimTypes.Htu,
                    "DPoP proof 'htu' claim does not match the request URI.",
                    DpopValidationFailureType.HtuMismatch);
            }

            if (!proofToken.TryGetPayloadValue(DpopClaimTypes.Iat, out long iat))
            {
                return new DpopProofValidationError(
                    "DPoP proof is missing the 'iat' claim.",
                    DpopValidationFailureType.IatMissing);
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
                return new DpopProofValidationError(
                    "DPoP proof has expired.",
                    DpopValidationFailureType.ProofExpired);
            }

            if (issuedAt - now > TimeSpan.FromSeconds(options.ClockSkewInSeconds))
            {
                return new DpopProofValidationError(
                    "DPoP proof 'iat' is too far in the future.",
                    DpopValidationFailureType.ProofIssuedInFuture);
            }

            if (!proofToken.TryGetPayloadValue(DpopClaimTypes.Jti, out string jtiValue) ||
                string.IsNullOrEmpty(jtiValue))
            {
                return new DpopProofClaimValidationError(
                    DpopClaimTypes.Jti,
                    "DPoP proof is missing the 'jti' claim.",
                    DpopValidationFailureType.JtiMissing);
            }

            if (options.ExpectedNonce != null)
            {
                if (string.IsNullOrWhiteSpace(options.ExpectedNonce))
                {
                    return new DpopProofValidationError(
                        "Server nonce configuration error: ExpectedNonce is empty or whitespace.",
                        DpopValidationFailureType.InvalidConfiguration);
                }

                if (!proofToken.TryGetPayloadValue(DpopClaimTypes.Nonce, out string nonceValue) ||
                    string.IsNullOrEmpty(nonceValue))
                {
                    return new DpopNonceRequiredError("DPoP nonce is required.");
                }

                if (!AreEqualUtf8(options.ExpectedNonce, nonceValue))
                {
                    return new DpopProofClaimValidationError(
                        DpopClaimTypes.Nonce,
                        "DPoP nonce validation failed.",
                        DpopValidationFailureType.NonceMismatch);
                }
            }

            if (!proofToken.TryGetPayloadValue(DpopClaimTypes.Ath, out string athValue) ||
                string.IsNullOrEmpty(athValue))
            {
                return new DpopProofClaimValidationError(
                    DpopClaimTypes.Ath,
                    "DPoP proof is missing the 'ath' claim.",
                    DpopValidationFailureType.AthMissing);
            }

            string expectedAth = ComputeAccessTokenHash(accessToken);
            if (!AreEqualUtf8(athValue, expectedAth))
            {
                return new DpopProofClaimValidationError(
                    DpopClaimTypes.Ath,
                    "DPoP proof 'ath' claim does not match the access token hash.",
                    DpopValidationFailureType.AthMismatch);
            }

            string thumbprint = ComputeJwkThumbprint(jwk);
            if (!AreEqualUtf8(expectedCnfJkt, thumbprint))
            {
                return new DpopCnfThumbprintMismatchError(
                    "DPoP proof JWK thumbprint does not match the access token cnf.jkt claim.");
            }

            if (options.JtiReplayCache != null)
            {
                var jtiExpiration = issuedAt.Add(maxAge);
                bool added = await options.JtiReplayCache
                    .TryAddAsync(jtiValue, jtiExpiration, cancellationToken)
                    .ConfigureAwait(false);

                if (!added)
                {
                    return new DpopProofClaimValidationError(
                        DpopClaimTypes.Jti,
                        "DPoP proof 'jti' has already been used (replay detected).",
                        DpopValidationFailureType.JtiReplayDetected);
                }
            }

            string? proofNonce = proofToken.TryGetPayloadValue(
                DpopClaimTypes.Nonce,
                out string nonce)
                    ? nonce
                    : null;

            return new ValidatedDpopProof(thumbprint, proofNonce);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return new DpopProofValidationError(
                "DPoP proof validation failed.",
                DpopValidationFailureType.UnexpectedError,
                ex);
        }
    }

    private static DpopValidationResult ToPublicResult(
        ValidationResult<ValidatedDpopProof, ValidationError> result)
    {
        if (result.Succeeded)
            return DpopValidationResult.Success(result.Result!.Nonce);

        return result.Error switch
        {
            DpopNonceRequiredError =>
                DpopValidationResult.NonceRequired(),

            DpopProofClaimValidationError error
                when error.DpopFailureType == DpopValidationFailureType.NonceMismatch =>
                DpopValidationResult.NonceValidationFailed(),

            DpopProofValidationError error =>
                DpopValidationResult.Failed(
                    error.Message,
                    error.DpopFailureType,
                    error.InnerException),

            SignatureValidationError error =>
                DpopValidationResult.Failed(
                    "DPoP proof signature validation failed.",
                    DpopValidationFailureType.SignatureInvalid,
                    error.InnerException),

            _ =>
                DpopValidationResult.Failed(
                    "DPoP proof validation failed.",
                    DpopValidationFailureType.UnexpectedError,
                    result.Error!.InnerException),
        };
    }

    private sealed class DpopPassThroughValidators :
        IAudienceValidator,
        IIssuerValidator,
        ILifetimeValidator
    {
        public ValidationResult<string, ValidationError> ValidateAudience(
            IList<string> tokenAudiences,
            SecurityToken? securityToken,
            ValidationParameters validationParameters,
            CallContext callContext)
            => string.Empty;

        public Task<ValidationResult<ValidatedIssuer, ValidationError>> ValidateIssuerAsync(
            string issuer,
            SecurityToken securityToken,
            ValidationParameters validationParameters,
            CallContext callContext,
            CancellationToken cancellationToken)
            => Task.FromResult<ValidationResult<ValidatedIssuer, ValidationError>>(
                new ValidatedIssuer(
                    issuer ?? string.Empty,
                    IssuerValidationSource.NotValidated));

        public ValidationResult<ValidatedLifetime, ValidationError> ValidateLifetime(
            DateTime? notBefore,
            DateTime? expires,
            SecurityToken? securityToken,
            ValidationParameters validationParameters,
            CallContext callContext)
            => new ValidatedLifetime(notBefore, expires);
    }

    private sealed class DpopSignatureValidator : ISignatureValidator
    {
        public ValidationResult<SecurityKey, ValidationError> ValidateSignature(
            SecurityToken token,
            ValidationParameters validationParameters,
            BaseConfiguration? configuration,
            CallContext callContext)
        {
            JsonWebToken proofToken = (JsonWebToken)token;
            SecurityKey key = validationParameters.SigningKeys[0];
            CryptoProviderFactory factory =
                key.CryptoProviderFactory ?? CryptoProviderFactory.Default;

            SignatureProvider? provider = null;
            try
            {
                provider = factory.CreateForVerifying(
                    key,
                    proofToken.Alg,
                    cacheProvider: false);

                if (VerifyProofSignature(proofToken, provider!))
                {
                    proofToken.SigningKey = key;
                    return key;
                }

                return new SignatureValidationError(
                    new MessageDetail("DPoP proof signature validation failed."),
                    SignatureValidationFailure.ValidationFailed,
                    ValidationError.GetCurrentStackFrame());
            }
            finally
            {
                if (provider is not null)
                {
                    try
                    {
                        factory.ReleaseSignatureProvider(provider);
                    }
#pragma warning disable CA1031 // Do not catch general exception types
                    catch (Exception ex)
#pragma warning restore CA1031
                    {
                        RecordSignatureProviderReleaseException(callContext, ex);
                    }
                }
            }
        }
    }

    private static void RecordSignatureProviderReleaseException(CallContext callContext, Exception exception)
    {
        callContext.PropertyBag ??= new Dictionary<string, object>();
        callContext.PropertyBag[SignatureProviderReleaseExceptionKey] = exception;
    }

    private static ValidationError? ConsumeSignatureProviderReleaseException(CallContext callContext)
    {
        if (callContext.PropertyBag is null
            || !callContext.PropertyBag.TryGetValue(SignatureProviderReleaseExceptionKey, out object? boxed)
            || boxed is not Exception exception)
        {
            return null;
        }

        callContext.PropertyBag.Remove(SignatureProviderReleaseExceptionKey);

        if (exception is OperationCanceledException)
            ExceptionDispatchInfo.Capture(exception).Throw();

        return new DpopProofValidationError(
            "DPoP proof validation failed.",
            DpopValidationFailureType.UnexpectedError,
            exception);
    }
#nullable restore
}
