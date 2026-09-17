// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Runtime.ExceptionServices;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Dpop.Experimental;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Tokens.Experimental;

#nullable enable
namespace Microsoft.IdentityModel.Dpop;

public partial class DpopProofValidator
{
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

#pragma warning disable CA1031 // Do not catch general exception types
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
                TokenReplayValidator = s_passThroughValidators,
                SignatureValidator = s_dpopSignatureValidator,
                TryAllSigningKeys = false,
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
                    return new DpopProofValidationError(
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
#pragma warning restore CA1031
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
        ILifetimeValidator,
        ITokenReplayValidator
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

        public ValidationResult<DateTime?, ValidationError> ValidateTokenReplay(
            DateTime? expirationTime,
            string securityToken,
            ValidationParameters validationParameters,
            CallContext callContext)
            => expirationTime;
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
}
