// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Configs;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Microsoft.IdentityModel.Benchmarks
{
    // dotnet run -c release -f net8.0 --filter Microsoft.IdentityModel.Benchmarks.ActorClaimBenchmarks*
    //
    // End-to-end benchmarks for actor ("act") claim support. Each scenario is measured in three
    // phases (grouped by category):
    //   * Actor_E2E      -> CreateToken + ValidateTokenAsync + force actor-chain materialization
    //   * Actor_Create   -> CreateToken only (isolates serialization, incl. the degrade-to-string path)
    //   * Actor_Validate -> ValidateTokenAsync only (isolates deserialization / actor-chain read)
    //
    // "MaxDepthN_NestedM" means JsonWebTokenHandler.MaxActorChainLength == N with an actor chain M
    // levels deep. When M > N the chain overflows: on write the remainder is serialized as a
    // JSON-text string, on read it is retained as an "act" claim rather than expanded into Actor.
    // MaxActorChainLength is a process-wide static, so every benchmark sets it explicitly (the
    // assignment is ~1ns and negligible against the microsecond-scale token operations).
    [GroupBenchmarksBy(BenchmarkLogicalGroupRule.ByCategory)]
    public class ActorClaimBenchmarks
    {
        private JsonWebTokenHandler _jsonWebTokenHandler;
        private TokenValidationParameters _tokenValidationParameters;

        // Descriptors (input for Create / E2E).
        private SecurityTokenDescriptor _descNoActor;
        private SecurityTokenDescriptor _descNested1;
        private SecurityTokenDescriptor _descNested2;
        private SecurityTokenDescriptor _descNested4;
        private SecurityTokenDescriptor _descNested5;
        private SecurityTokenDescriptor _descLegacyActort;

        // Pre-created tokens (input for Validate), each built with its scenario's MaxActorChainLength.
        private string _tokNoActor;
        private string _tokNested1;
        private string _tokNested2;
        private string _tokNested4;
        private string _tokNested5;
        private string _tokLegacyActort;

        [GlobalSetup]
        public void Setup()
        {
            _jsonWebTokenHandler = new JsonWebTokenHandler();

            _tokenValidationParameters = new TokenValidationParameters
            {
                ValidIssuer = BenchmarkUtils.Issuer,
                ValidAudience = BenchmarkUtils.Audience,
                IssuerSigningKey = BenchmarkUtils.SigningCredentialsRsaSha256.Key,
                ValidateLifetime = false,
            };

            _descNoActor = Descriptor(BuildSubjectWithActorChain(0));
            _descNested1 = Descriptor(BuildSubjectWithActorChain(1));
            _descNested2 = Descriptor(BuildSubjectWithActorChain(2));
            _descNested4 = Descriptor(BuildSubjectWithActorChain(4));
            _descNested5 = Descriptor(BuildSubjectWithActorChain(5));

            // Legacy "actort": the handler never *writes* actort; a caller supplies it as a JWT string
            // in the Claims dictionary (this is what legacy JwtSecurityTokenHandler tokens look like).
            string actorJwt = _jsonWebTokenHandler.CreateToken(Descriptor(BuildSubjectWithActorChain(0)));
            _descLegacyActort = Descriptor(new CaseSensitiveClaimsIdentity(new[] { new Claim("sub", "user-1") }));
            _descLegacyActort.Claims = new Dictionary<string, object> { { "actort", actorJwt } };

            // Pre-create the tokens used by the Validate-only benchmarks, each at its scenario's depth.
            JsonWebTokenHandler.MaxActorChainLength = 1;
            _tokNoActor = _jsonWebTokenHandler.CreateToken(_descNoActor);
            _tokNested1 = _jsonWebTokenHandler.CreateToken(_descNested1);
            _tokNested2 = _jsonWebTokenHandler.CreateToken(_descNested2);
            _tokNested5 = _jsonWebTokenHandler.CreateToken(_descNested5);
            _tokLegacyActort = _jsonWebTokenHandler.CreateToken(_descLegacyActort);

            JsonWebTokenHandler.MaxActorChainLength = 5;
            _tokNested4 = _jsonWebTokenHandler.CreateToken(_descNested4);
        }

        [GlobalCleanup]
        public void Cleanup() => JsonWebTokenHandler.MaxActorChainLength = 1;

        private static SecurityTokenDescriptor Descriptor(ClaimsIdentity subject) => new SecurityTokenDescriptor
        {
            Subject = subject,
            Issuer = BenchmarkUtils.Issuer,
            Audience = BenchmarkUtils.Audience,
            SigningCredentials = BenchmarkUtils.SigningCredentialsRsaSha256,
        };

        // Builds a subject whose ClaimsIdentity.Actor chain is <paramref name="actorLevels"/> deep
        // (0 = no actor).
        private static ClaimsIdentity BuildSubjectWithActorChain(int actorLevels)
        {
            var subject = new CaseSensitiveClaimsIdentity(new[] { new Claim("sub", "user-1"), new Claim("name", "User One") });
            var current = subject;
            for (int i = 1; i <= actorLevels; i++)
            {
                var actor = new CaseSensitiveClaimsIdentity(new[] { new Claim("sub", $"actor-{i}"), new Claim("role", "worker") });
                current.Actor = actor;
                current = actor;
            }

            return subject;
        }

        // Creates a token, validates it, and returns the actor identity to force the actor chain to be
        // materialized inside the measured region (ClaimsIdentity is built lazily on access).
        private async Task<ClaimsIdentity> RoundTripAsync(SecurityTokenDescriptor descriptor)
        {
            string token = _jsonWebTokenHandler.CreateToken(descriptor);
            var result = await _jsonWebTokenHandler.ValidateTokenAsync(token, _tokenValidationParameters).ConfigureAwait(false);
            return result.ClaimsIdentity?.Actor;
        }

        private async Task<ClaimsIdentity> ValidateAsync(string token)
        {
            var result = await _jsonWebTokenHandler.ValidateTokenAsync(token, _tokenValidationParameters).ConfigureAwait(false);
            return result.ClaimsIdentity?.Actor;
        }

        // ------------------------------------------------------------------ E2E (create + validate)

        [BenchmarkCategory("Actor_E2E"), Benchmark(Baseline = true)]
        public async Task<ClaimsIdentity> E2E_NoActor()
        {
            JsonWebTokenHandler.MaxActorChainLength = 1;
            return await RoundTripAsync(_descNoActor).ConfigureAwait(false);
        }

        [BenchmarkCategory("Actor_E2E"), Benchmark]
        public async Task<ClaimsIdentity> E2E_MaxDepth1_Nested1()
        {
            JsonWebTokenHandler.MaxActorChainLength = 1;
            return await RoundTripAsync(_descNested1).ConfigureAwait(false);
        }

        [BenchmarkCategory("Actor_E2E"), Benchmark]
        public async Task<ClaimsIdentity> E2E_MaxDepth1_Nested2_Degrade()
        {
            JsonWebTokenHandler.MaxActorChainLength = 1;
            return await RoundTripAsync(_descNested2).ConfigureAwait(false);
        }

        [BenchmarkCategory("Actor_E2E"), Benchmark]
        public async Task<ClaimsIdentity> E2E_MaxDepth1_Nested5_DeepDegrade()
        {
            JsonWebTokenHandler.MaxActorChainLength = 1;
            return await RoundTripAsync(_descNested5).ConfigureAwait(false);
        }

        [BenchmarkCategory("Actor_E2E"), Benchmark]
        public async Task<ClaimsIdentity> E2E_MaxDepth5_Nested4()
        {
            JsonWebTokenHandler.MaxActorChainLength = 5;
            return await RoundTripAsync(_descNested4).ConfigureAwait(false);
        }

        [BenchmarkCategory("Actor_E2E"), Benchmark]
        public async Task<ClaimsIdentity> E2E_LegacyActort_MaxDepth1()
        {
            JsonWebTokenHandler.MaxActorChainLength = 1;
            return await RoundTripAsync(_descLegacyActort).ConfigureAwait(false);
        }

        // ------------------------------------------------------------------ Create (serialize only)

        [BenchmarkCategory("Actor_Create"), Benchmark(Baseline = true)]
        public string Create_NoActor()
        {
            JsonWebTokenHandler.MaxActorChainLength = 1;
            return _jsonWebTokenHandler.CreateToken(_descNoActor);
        }

        [BenchmarkCategory("Actor_Create"), Benchmark]
        public string Create_MaxDepth1_Nested1()
        {
            JsonWebTokenHandler.MaxActorChainLength = 1;
            return _jsonWebTokenHandler.CreateToken(_descNested1);
        }

        [BenchmarkCategory("Actor_Create"), Benchmark]
        public string Create_MaxDepth1_Nested2_Degrade()
        {
            JsonWebTokenHandler.MaxActorChainLength = 1;
            return _jsonWebTokenHandler.CreateToken(_descNested2);
        }

        [BenchmarkCategory("Actor_Create"), Benchmark]
        public string Create_MaxDepth1_Nested5_DeepDegrade()
        {
            JsonWebTokenHandler.MaxActorChainLength = 1;
            return _jsonWebTokenHandler.CreateToken(_descNested5);
        }

        [BenchmarkCategory("Actor_Create"), Benchmark]
        public string Create_MaxDepth5_Nested4()
        {
            JsonWebTokenHandler.MaxActorChainLength = 5;
            return _jsonWebTokenHandler.CreateToken(_descNested4);
        }

        [BenchmarkCategory("Actor_Create"), Benchmark]
        public string Create_LegacyActort_MaxDepth1()
        {
            JsonWebTokenHandler.MaxActorChainLength = 1;
            return _jsonWebTokenHandler.CreateToken(_descLegacyActort);
        }

        // ------------------------------------------------------------------ Validate (deserialize only)

        [BenchmarkCategory("Actor_Validate"), Benchmark(Baseline = true)]
        public async Task<ClaimsIdentity> Validate_NoActor()
        {
            JsonWebTokenHandler.MaxActorChainLength = 1;
            return await ValidateAsync(_tokNoActor).ConfigureAwait(false);
        }

        [BenchmarkCategory("Actor_Validate"), Benchmark]
        public async Task<ClaimsIdentity> Validate_MaxDepth1_Nested1()
        {
            JsonWebTokenHandler.MaxActorChainLength = 1;
            return await ValidateAsync(_tokNested1).ConfigureAwait(false);
        }

        [BenchmarkCategory("Actor_Validate"), Benchmark]
        public async Task<ClaimsIdentity> Validate_MaxDepth1_Nested2_Degrade()
        {
            JsonWebTokenHandler.MaxActorChainLength = 1;
            return await ValidateAsync(_tokNested2).ConfigureAwait(false);
        }

        [BenchmarkCategory("Actor_Validate"), Benchmark]
        public async Task<ClaimsIdentity> Validate_MaxDepth1_Nested5_DeepDegrade()
        {
            JsonWebTokenHandler.MaxActorChainLength = 1;
            return await ValidateAsync(_tokNested5).ConfigureAwait(false);
        }

        [BenchmarkCategory("Actor_Validate"), Benchmark]
        public async Task<ClaimsIdentity> Validate_MaxDepth5_Nested4()
        {
            JsonWebTokenHandler.MaxActorChainLength = 5;
            return await ValidateAsync(_tokNested4).ConfigureAwait(false);
        }

        [BenchmarkCategory("Actor_Validate"), Benchmark]
        public async Task<ClaimsIdentity> Validate_LegacyActort_MaxDepth1()
        {
            JsonWebTokenHandler.MaxActorChainLength = 1;
            return await ValidateAsync(_tokLegacyActort).ConfigureAwait(false);
        }
    }
}
