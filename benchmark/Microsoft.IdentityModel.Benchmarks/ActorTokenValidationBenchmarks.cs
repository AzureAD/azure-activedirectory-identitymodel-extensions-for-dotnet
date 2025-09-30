// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using BenchmarkDotNet.Attributes;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.TestUtils;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Tokens.Experimental;

namespace Microsoft.IdentityModel.Benchmarks
{
    /// <summary>
    /// Benchmarks for measuring the performance impact of CanReadToken checks
    /// in actor token validation scenarios.
    /// Compares performance with and without the security fix.
    /// </summary>
    public class ActorTokenValidationBenchmarks
    {
        private JsonWebTokenHandler _handler;
        private JsonWebTokenHandlerWithoutCanReadTokenCheck _handlerWithoutCheck;
        private string _tokenWithValidActor;
        private string _tokenWithLongActor;
        private string _tokenWithMalformedActor;
        private ValidationParameters _validationParameters;
        private CallContext _callContext;

        [GlobalSetup]
        public void Setup()
        {
            _handler = new JsonWebTokenHandler();
            _handlerWithoutCheck = new JsonWebTokenHandlerWithoutCanReadTokenCheck();
            _callContext = new CallContext();

            // Setup validation parameters
            _validationParameters = ValidationUtils.CreateValidationParameters(
                audiences: new List<string> { Default.Audience },
                issuers: new List<string> { Default.Issuer },
                signingKeys: new List<SecurityKey> { KeyingMaterial.JsonWebKeyRsa256SigningCredentials.Key });
            _validationParameters.ValidateActor = true;
            _validationParameters.ActorValidationParameters = ValidationUtils.CreateValidationParameters(
                audiences: new List<string> { Default.Audience },
                issuers: new List<string> { Default.Issuer },
                signingKeys: new List<SecurityKey> { KeyingMaterial.JsonWebKeyRsa256SigningCredentials.Key });

            // Create a valid actor token
            var validActorToken = _handler.CreateToken(new SecurityTokenDescriptor
            {
                Subject = ClaimSets.DefaultClaimsIdentity,
                SigningCredentials = KeyingMaterial.JsonWebKeyRsa256SigningCredentials,
                Audience = Default.Audience,
                Issuer = Default.Issuer
            });

            // Create main token with valid actor
            _tokenWithValidActor = _handler.CreateToken(new SecurityTokenDescriptor
            {
                Subject = ClaimSets.DefaultClaimsIdentity,
                SigningCredentials = KeyingMaterial.JsonWebKeyRsa256SigningCredentials,
                Audience = Default.Audience,
                Issuer = Default.Issuer,
                Claims = new System.Collections.Generic.Dictionary<string, object>
                {
                    { JwtRegisteredClaimNames.Actort, validActorToken }
                }
            });

            // Create token with overly long actor (will be rejected by CanReadToken)
            var longActorToken = new string('a', ValidationParameters.DefaultMaximumTokenSizeInBytes + 1);
            _tokenWithLongActor = _handler.CreateToken(new SecurityTokenDescriptor
            {
                Subject = ClaimSets.DefaultClaimsIdentity,
                SigningCredentials = KeyingMaterial.JsonWebKeyRsa256SigningCredentials,
                Audience = Default.Audience,
                Issuer = Default.Issuer,
                Claims = new System.Collections.Generic.Dictionary<string, object>
                {
                    { JwtRegisteredClaimNames.Actort, longActorToken }
                }
            });

            // Create token with malformed actor (will be rejected by CanReadToken)
            var malformedActorToken = "not.a.valid.jwt.token";
            _tokenWithMalformedActor = _handler.CreateToken(new SecurityTokenDescriptor
            {
                Subject = ClaimSets.DefaultClaimsIdentity,
                SigningCredentials = KeyingMaterial.JsonWebKeyRsa256SigningCredentials,
                Audience = Default.Audience,
                Issuer = Default.Issuer,
                Claims = new System.Collections.Generic.Dictionary<string, object>
                {
                    { JwtRegisteredClaimNames.Actort, malformedActorToken }
                }
            });
        }

        // ==== COMPARISON: WITH vs WITHOUT CanReadToken Check ====

        [Benchmark(Baseline = true)]
        public async Task<ValidationResult<ValidatedToken, ValidationError>> ValidateToken_ValidActor_With_CanReadToken()
        {
            // Current implementation WITH CanReadToken security check
            return await _handler.ValidateTokenAsync(_tokenWithValidActor, _validationParameters, _callContext, CancellationToken.None);
        }

        [Benchmark]
        public async Task<ValidationResult<ValidatedToken, ValidationError>> ValidateToken_ValidActor_Without_CanReadToken()
        {
            // Original implementation WITHOUT CanReadToken security check
            return await _handlerWithoutCheck.ValidateTokenAsync(_tokenWithValidActor, _validationParameters, _callContext, CancellationToken.None);
        }

        // ==== FAST-FAIL SCENARIOS ====

        [Benchmark]
        public async Task<ValidationResult<ValidatedToken, ValidationError>> ValidateToken_LongActor_With_CanReadToken()
        {
            // This should fail fast due to CanReadToken check
            return await _handler.ValidateTokenAsync(_tokenWithLongActor, _validationParameters, _callContext, CancellationToken.None);
        }

        [Benchmark]
        public async Task<ValidationResult<ValidatedToken, ValidationError>> ValidateToken_LongActor_Without_CanReadToken()
        {
            // This will try to parse the long token, demonstrating slower failure
            return await _handlerWithoutCheck.ValidateTokenAsync(_tokenWithLongActor, _validationParameters, _callContext, CancellationToken.None);
        }

        [Benchmark]
        public async Task<ValidationResult<ValidatedToken, ValidationError>> ValidateToken_MalformedActor_With_CanReadToken()
        {
            // This should fail fast due to CanReadToken check
            return await _handler.ValidateTokenAsync(_tokenWithMalformedActor, _validationParameters, _callContext, CancellationToken.None);
        }

        [Benchmark]
        public async Task<ValidationResult<ValidatedToken, ValidationError>> ValidateToken_MalformedActor_Without_CanReadToken()
        {
            // This will try to parse the malformed token, demonstrating slower failure
            return await _handlerWithoutCheck.ValidateTokenAsync(_tokenWithMalformedActor, _validationParameters, _callContext, CancellationToken.None);
        }

        // ==== RAW CANREADTOKEN PERFORMANCE ====

        [Benchmark]
        public bool CanReadToken_ValidActor()
        {
            // Measure the cost of the CanReadToken check itself
            var validActorToken = _handler.CreateToken(new SecurityTokenDescriptor
            {
                Subject = ClaimSets.DefaultClaimsIdentity,
                SigningCredentials = KeyingMaterial.JsonWebKeyRsa256SigningCredentials,
                Audience = Default.Audience,
                Issuer = Default.Issuer
            });
            return _handler.CanReadToken(validActorToken);
        }

        [Benchmark]
        public bool CanReadToken_LongToken()
        {
            // Measure the cost of the CanReadToken check for long tokens
            var longToken = new string('a', ValidationParameters.DefaultMaximumTokenSizeInBytes + 1);
            return _handler.CanReadToken(longToken);
        }

        [Benchmark]
        public bool CanReadToken_MalformedToken()
        {
            // Measure the cost of the CanReadToken check for malformed tokens
            return _handler.CanReadToken("not.a.valid.jwt.token");
        }
    }

    /// <summary>
    /// A JsonWebTokenHandler without the CanReadToken security checks,
    /// mimicking the original vulnerable implementation for performance comparison.
    /// </summary>
    internal class JsonWebTokenHandlerWithoutCanReadTokenCheck : JsonWebTokenHandler
    {
        internal override async Task<ValidationResult<ValidatedToken, ValidationError>> ValidateTokenAsync(
            string token,
            ValidationParameters validationParameters,
            CallContext callContext,
            CancellationToken cancellationToken)
        {
            if (string.IsNullOrEmpty(token))
            {
                return ValidationError.NullParameter(
                    nameof(token),
                    ValidationError.GetCurrentStackFrame());
            }

            if (validationParameters is null)
            {
                return ValidationError.NullParameter(
                    nameof(validationParameters),
                    ValidationError.GetCurrentStackFrame());
            }

            if (token.Length > MaximumTokenSizeInBytes)
            {
                return new ValidationError(
                    new MessageDetail(
                        "IDX10209: Token has length: '{0}' which is larger than the maximum token size: '{1}'.",
                        LogHelper.MarkAsNonPII(token.Length),
                        LogHelper.MarkAsNonPII(MaximumTokenSizeInBytes)),
                    ValidationFailureType.SecurityTokenTooLarge,
                    ValidationError.GetCurrentStackFrame());
            }

            // Read token WITHOUT CanReadToken check (original vulnerable behavior)
            ValidationResult<SecurityToken, ValidationError> readResult = ReadToken(token, callContext);
            if (readResult.Succeeded)
            {
                ValidationResult<ValidatedToken, ValidationError> validationResult = await ValidateTokenAsync(
                    readResult.Result!,
                    validationParameters,
                    callContext,
                    cancellationToken)
                    .ConfigureAwait(false);

                if (validationResult.Succeeded)
                    return validationResult;
                else
                    return validationResult.Error!.AddCurrentStackFrame();
            }
            else
                return readResult.Error!.AddCurrentStackFrame();
        }

        internal override async Task<ValidationResult<ValidatedToken, ValidationError>> ValidateTokenAsync(
            SecurityToken securityToken,
            ValidationParameters validationParameters,
            CallContext callContext,
            CancellationToken cancellationToken)
        {
            if (securityToken is JsonWebToken jsonWebToken)
            {
                return await ValidateJWSAsync(jsonWebToken, validationParameters, null, callContext, cancellationToken).ConfigureAwait(false);
            }

            return new ValidationError(
                new MessageDetail("Unsupported token type"),
                ValidationFailureType.TokenReadingFailed,
                ValidationError.GetCurrentStackFrame());
        }

        private async ValueTask<ValidationResult<ValidatedToken, ValidationError>> ValidateJWSAsync(
            JsonWebToken jsonWebToken,
            ValidationParameters validationParameters,
            BaseConfiguration configuration,
            CallContext callContext,
            CancellationToken cancellationToken)
        {
            // Simulate the original validation logic but skip CanReadToken checks for actor tokens
            ValidationResult<ValidatedToken, ValidationError>? actorResult = null;
            if (validationParameters.ValidateActor && !string.IsNullOrWhiteSpace(jsonWebToken.Actor))
            {
                // ORIGINAL VULNERABLE CODE: No CanReadToken check before ReadToken
                ValidationResult<SecurityToken, ValidationError> readResult = ReadToken(jsonWebToken.Actor, callContext);
                if (!readResult.Succeeded)
                    return readResult.Error!.AddCurrentStackFrame();

                if (validationParameters.ActorValidationParameters is null)
                    return ValidationError.NullParameter(
                        nameof(validationParameters.ActorValidationParameters),
                        ValidationError.GetCurrentStackFrame());

                JsonWebToken actorToken = (readResult.Result as JsonWebToken)!;
                actorResult = await ValidateJWSAsync(
                    actorToken,
                    validationParameters.ActorValidationParameters,
                    configuration,
                    callContext,
                    cancellationToken).ConfigureAwait(false);

                if (!actorResult.Value.Succeeded)
                    return actorResult.Value.Error!.AddCurrentStackFrame();
            }

            // For simplicity, return a successful result for benchmarking purposes
            // In real scenarios, this would include all other validation steps
            return new ValidatedToken(jsonWebToken, this, validationParameters)
            {
                ActorValidationResult = actorResult?.Result
            };
        }
    }
}