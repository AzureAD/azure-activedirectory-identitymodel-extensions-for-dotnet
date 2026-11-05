// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Tokens.Experimental;

namespace Microsoft.IdentityModel.Protocols.SignedHttpRequest
{
    /// <summary>
    /// A class which contains useful methods related to processing of SignedHttpRequest protocol.
    /// </summary>
    public static partial class SignedHttpRequestUtilities
    {
#nullable enable
        private sealed class NoOpAlgorithmValidator : IAlgorithmValidator
        {
            public ValidationResult<string, ValidationError> ValidateAlgorithm(
                string? algorithm,
                SecurityToken securityToken,
                ValidationParameters validationParameters,
                CallContext callContext)
            {
                return algorithm ?? string.Empty;
            }
        }

        private sealed class NoOpAudienceValidator : IAudienceValidator
        {
            public ValidationResult<string, ValidationError> ValidateAudience(
                IList<string> tokenAudiences,
                SecurityToken? securityToken,
                ValidationParameters validationParameters,
                CallContext callContext)
            {
                return "skipped";
            }
        }

        private sealed class NoOpIssuerValidator : IIssuerValidator
        {
            public Task<ValidationResult<ValidatedIssuer, ValidationError>> ValidateIssuerAsync(
                string issuer,
                SecurityToken securityToken,
                ValidationParameters validationParameters,
                CallContext callContext,
                CancellationToken cancellationToken)
            {
                return Task.FromResult(new ValidationResult<ValidatedIssuer, ValidationError>(
                    new ValidatedIssuer(issuer, IssuerValidationSource.NotValidated)));
            }
        }

        private sealed class NoOpSignatureKeyValidator : ISignatureKeyValidator
        {
            public ValidationResult<ValidatedSignatureKey, ValidationError> ValidateSignatureKey(
                SecurityKey signingKey,
                SecurityToken securityToken,
                ValidationParameters validationParameters,
                CallContext callContext)
            {
                return new ValidatedSignatureKey(null, null, null);
            }
        }

        private sealed class NoOpLifetimeValidator : ILifetimeValidator
        {
            public ValidationResult<ValidatedLifetime, ValidationError> ValidateLifetime(
                DateTime? notBefore,
                DateTime? expires,
                SecurityToken? securityToken,
                ValidationParameters validationParameters,
                CallContext callContext)
            {
                return new ValidatedLifetime(notBefore, expires);
            }
        }

        private sealed class NoOpSignatureValidator : ISignatureValidator
        {
            public ValidationResult<SecurityKey, ValidationError> ValidateSignature(
                SecurityToken token,
                ValidationParameters validationParameters,
                BaseConfiguration? configuration,
                CallContext callContext)
            {
                // A placeholder key satisfies the result contract; no signature is verified.
                return new ValidationResult<SecurityKey, ValidationError>(new JsonWebKey());
            }
        }

        private sealed class NoOpTokenReplayValidator : ITokenReplayValidator
        {
            public ValidationResult<DateTime?, ValidationError> ValidateTokenReplay(
                DateTime? expirationTime,
                string securityToken,
                ValidationParameters validationParameters,
                CallContext callContext)
            {
                return expirationTime;
            }
        }

        private sealed class NoOpTokenTypeValidator : ITokenTypeValidator
        {
            public ValidationResult<ValidatedTokenType, ValidationError> ValidateTokenType(
                string? type,
                SecurityToken? securityToken,
                ValidationParameters validationParameters,
                CallContext callContext)
            {
                return new ValidatedTokenType("skipped", 0);
            }
        }
#nullable restore

        internal static async Task<JsonWebKey> DecryptSymmetricPopKeyAsync(JsonWebTokenHandler jwtTokenHandler, string jwe, Experimental.SignedHttpRequestValidationContext signedHttpRequestValidationContext, CancellationToken cancellationToken)
        {
            if (string.IsNullOrEmpty(jwe))
                throw LogHelper.LogArgumentNullException(nameof(jwe));

            var jweJwt = jwtTokenHandler.ReadJsonWebToken(jwe);

            IEnumerable<SecurityKey> decryptionKeys;
            if (signedHttpRequestValidationContext.SignedHttpRequestValidationParameters.CnfDecryptionKeysResolverAsync != null)
                decryptionKeys = await signedHttpRequestValidationContext.SignedHttpRequestValidationParameters.CnfDecryptionKeysResolverAsync(jweJwt, cancellationToken).ConfigureAwait(false);
            else
                decryptionKeys = signedHttpRequestValidationContext.SignedHttpRequestValidationParameters.CnfDecryptionKeys;

            if (decryptionKeys == null || !decryptionKeys.Any())
                throw LogHelper.LogExceptionMessage(new SignedHttpRequestInvalidPopKeyException(LogHelper.FormatInvariant(LogMessages.IDX23017)));

            var tokenDecryptionParameters = new ValidationParameters()
            {
                IssuerValidatorAsync = new NoOpIssuerValidator(),
                LifetimeValidator = new NoOpLifetimeValidator(),
                AudienceValidator = new NoOpAudienceValidator(),
                SignatureKeyValidator = new NoOpSignatureKeyValidator()
            };
            foreach (SecurityKey decryptionKey in decryptionKeys)
                tokenDecryptionParameters.DecryptionKeys.Add(decryptionKey);

            try
            {
                ValidationResult<string, ValidationError> result = jwtTokenHandler.DecryptToken(jweJwt, tokenDecryptionParameters, null, null);
                if (!result.Succeeded)
                    throw result.Error.InnerException;
                return new JsonWebKey(result.Result);
            }
            catch (Exception e)
            {
                throw LogHelper.LogExceptionMessage(new SignedHttpRequestInvalidPopKeyException(
                    LogHelper.FormatInvariant(
                        LogMessages.IDX23018,
                        LogHelper.MarkAsNonPII(string.Join(", ", decryptionKeys.Select(x => x?.KeyId ?? "Null"))),
                        e),
                    e));
            }
        }
    }
}
