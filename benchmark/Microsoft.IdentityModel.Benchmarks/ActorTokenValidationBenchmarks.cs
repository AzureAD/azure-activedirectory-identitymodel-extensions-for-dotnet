// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using BenchmarkDotNet.Attributes;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.TestUtils;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Tokens.Experimental;

namespace Microsoft.IdentityModel.Benchmarks
{
    /// <summary>
    /// Benchmarks for measuring the performance impact of CanReadToken checks
    /// in actor token validation scenarios.
    /// </summary>
    public class ActorTokenValidationBenchmarks
    {
        private JsonWebTokenHandler _handler;
        private string _tokenWithValidActor;
        private string _tokenWithLongActor;
        private string _tokenWithMalformedActor;
        private ValidationParameters _validationParameters;
        private CallContext _callContext;

        [GlobalSetup]
        public void Setup()
        {
            _handler = new JsonWebTokenHandler();
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

        [Benchmark(Baseline = true)]
        public async Task<ValidationResult<ValidatedToken, ValidationError>> ValidateToken_ValidActor()
        {
            return await _handler.ValidateTokenAsync(_tokenWithValidActor, _validationParameters, _callContext, CancellationToken.None);
        }

        [Benchmark]
        public async Task<ValidationResult<ValidatedToken, ValidationError>> ValidateToken_LongActor_FastFail()
        {
            // This should fail fast due to CanReadToken check, demonstrating performance benefit
            return await _handler.ValidateTokenAsync(_tokenWithLongActor, _validationParameters, _callContext, CancellationToken.None);
        }

        [Benchmark]
        public async Task<ValidationResult<ValidatedToken, ValidationError>> ValidateToken_MalformedActor_FastFail()
        {
            // This should fail fast due to CanReadToken check, demonstrating performance benefit  
            return await _handler.ValidateTokenAsync(_tokenWithMalformedActor, _validationParameters, _callContext, CancellationToken.None);
        }

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
}