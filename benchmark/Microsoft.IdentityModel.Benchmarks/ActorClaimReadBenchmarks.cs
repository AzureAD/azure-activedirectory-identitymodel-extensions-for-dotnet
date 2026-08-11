// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;
using BenchmarkDotNet.Attributes;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Microsoft.IdentityModel.Benchmarks;

// dotnet run -c release -f net8.0 --filter Microsoft.IdentityModel.Benchmarks.ActorClaimReadBenchmarks*
//
// Deserialization (read-path) benchmarks for actor ("act") claim support: ValidateTokenAsync, then
// materialize ClaimsIdentity (which is built lazily) so the actor-expansion cost is measured.
//
// Covers: no actor, a single "act", a degraded "act" chain (chain deeper than MaxActorChainLength, so
// the overflow was written as a JSON-text string and is kept as a claim on read), and the legacy
// "actort" (unsigned nested-JWT) expansion path. MaxActorChainLength is a process-wide static.
[MemoryDiagnoser]
public class ActorClaimReadBenchmarks
{
    private JsonWebTokenHandler _handler;
    private TokenValidationParameters _validationParameters;
    private string _tokenNoActor;
    private string _tokenAct1;
    private string _tokenAct2Degrade;
    private string _tokenActort;

    [GlobalSetup]
    public void Setup()
    {
        _handler = new JsonWebTokenHandler();
        JsonWebTokenHandler.MaxActorChainLength = 1;

        _tokenNoActor = _handler.CreateToken(Descriptor(BuildSubjectWithActorChain(0)));
        _tokenAct1 = _handler.CreateToken(Descriptor(BuildSubjectWithActorChain(1)));
        _tokenAct2Degrade = _handler.CreateToken(Descriptor(BuildSubjectWithActorChain(2)));

        // Legacy actort: an actor JWT embedded as the "actort" claim (what older JwtSecurityTokenHandler
        // tokens look like). Read back-compat expands it into ClaimsIdentity.Actor.
        string actorJwt = _handler.CreateToken(new SecurityTokenDescriptor
        {
            Subject = new CaseSensitiveClaimsIdentity(new[] { new Claim("sub", "actor-1"), new Claim("role", "worker") }),
            SigningCredentials = BenchmarkUtils.SigningCredentialsRsaSha256,
        });
        _tokenActort = _handler.CreateToken(new SecurityTokenDescriptor
        {
            Subject = new CaseSensitiveClaimsIdentity(new[] { new Claim("sub", "user-1"), new Claim("name", "User One") }),
            Issuer = BenchmarkUtils.Issuer,
            Audience = BenchmarkUtils.Audience,
            SigningCredentials = BenchmarkUtils.SigningCredentialsRsaSha256,
            Claims = new Dictionary<string, object> { { "actort", actorJwt } },
        });

        _validationParameters = new TokenValidationParameters
        {
            ValidateIssuer = false,
            ValidateAudience = false,
            ValidateLifetime = false,
            IssuerSigningKey = BenchmarkUtils.SigningCredentialsRsaSha256.Key,
            ValidateIssuerSigningKey = true,
        };
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

    // Accessing result.ClaimsIdentity forces the (lazy) claims-identity + actor materialization.
    [Benchmark(Baseline = true)]
    public async Task<ClaimsIdentity> ValidateNoActor()
    {
        JsonWebTokenHandler.MaxActorChainLength = 1;
        var result = await _handler.ValidateTokenAsync(_tokenNoActor, _validationParameters).ConfigureAwait(false);
        return result.ClaimsIdentity;
    }

    [Benchmark]
    public async Task<ClaimsIdentity> ValidateAct1()
    {
        JsonWebTokenHandler.MaxActorChainLength = 1;
        var result = await _handler.ValidateTokenAsync(_tokenAct1, _validationParameters).ConfigureAwait(false);
        return result.ClaimsIdentity;
    }

    [Benchmark]
    public async Task<ClaimsIdentity> ValidateAct2_Degrade()
    {
        JsonWebTokenHandler.MaxActorChainLength = 1;
        var result = await _handler.ValidateTokenAsync(_tokenAct2Degrade, _validationParameters).ConfigureAwait(false);
        return result.ClaimsIdentity;
    }

    [Benchmark]
    public async Task<ClaimsIdentity> ValidateActort_Legacy()
    {
        JsonWebTokenHandler.MaxActorChainLength = 1;
        var result = await _handler.ValidateTokenAsync(_tokenActort, _validationParameters).ConfigureAwait(false);
        return result.ClaimsIdentity;
    }
}
