// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System.Security.Claims;
using BenchmarkDotNet.Attributes;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Microsoft.IdentityModel.Benchmarks
{
    // dotnet run -c release -f net8.0 --filter Microsoft.IdentityModel.Benchmarks.ActorClaimSerializationBenchmarks*
    //
    // Serialization (write-path) benchmarks for actor ("act") claim support: CreateToken only.
    //
    // "MaxDepthN_NestedM" means JsonWebTokenHandler.MaxActorChainLength == N with an actor chain M
    // levels deep. When M > N the chain overflows and, on write, the remainder is serialized as a
    // JSON-text string rather than nested "act" objects. MaxActorChainLength is a process-wide static,
    // so every benchmark sets it explicitly (the assignment is ~1ns and negligible against the
    // microsecond-scale token operations).
    public class ActorClaimSerializationBenchmarks
    {
        private JsonWebTokenHandler _jsonWebTokenHandler;
        private SecurityTokenDescriptor _descNoActor;
        private SecurityTokenDescriptor _descNested1;
        private SecurityTokenDescriptor _descNested2;
        private SecurityTokenDescriptor _descNested4;
        private SecurityTokenDescriptor _descNested5;

        [GlobalSetup]
        public void Setup()
        {
            _jsonWebTokenHandler = new JsonWebTokenHandler();
            _descNoActor = Descriptor(BuildSubjectWithActorChain(0));
            _descNested1 = Descriptor(BuildSubjectWithActorChain(1));
            _descNested2 = Descriptor(BuildSubjectWithActorChain(2));
            _descNested4 = Descriptor(BuildSubjectWithActorChain(4));
            _descNested5 = Descriptor(BuildSubjectWithActorChain(5));
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

        [Benchmark(Baseline = true)]
        public string NoActor()
        {
            JsonWebTokenHandler.MaxActorChainLength = 1;
            return _jsonWebTokenHandler.CreateToken(_descNoActor);
        }

        [Benchmark]
        public string MaxDepth1_Nested1()
        {
            JsonWebTokenHandler.MaxActorChainLength = 1;
            return _jsonWebTokenHandler.CreateToken(_descNested1);
        }

        [Benchmark]
        public string MaxDepth1_Nested2_Degrade()
        {
            JsonWebTokenHandler.MaxActorChainLength = 1;
            return _jsonWebTokenHandler.CreateToken(_descNested2);
        }

        [Benchmark]
        public string MaxDepth1_Nested5_DeepDegrade()
        {
            JsonWebTokenHandler.MaxActorChainLength = 1;
            return _jsonWebTokenHandler.CreateToken(_descNested5);
        }

        [Benchmark]
        public string MaxDepth5_Nested4()
        {
            JsonWebTokenHandler.MaxActorChainLength = 5;
            return _jsonWebTokenHandler.CreateToken(_descNested4);
        }
    }
}
