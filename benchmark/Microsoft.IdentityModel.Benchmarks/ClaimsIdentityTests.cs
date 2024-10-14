using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Configs;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Microsoft.IdentityModel.Benchmarks
{
    // dotnet run -c release -f net8.0 --filter Microsoft.IdentityModel.Benchmarks.ClaimsIdentityTests*

    [GroupBenchmarksBy(BenchmarkLogicalGroupRule.ByCategory)]
    public class ClaimsIdentityTests
    {
        private ClaimsIdentity _claimsIdentity;
        private SecurityTokenClaimsIdentity _newClaimsIdentity;
        private string _claimTypeToFind;
        private string _claimValueToFind;
        private Predicate<Claim> _findPredicate;
        private Predicate<Claim> _hasClaimPredicate;

        private JsonWebTokenHandler _jsonWebTokenHandler;
        private string _jwsWithExtendedClaims;
        private TokenValidationParameters _tokenValidationParameters;
        private TokenValidationParameters _newTokenValidationParameters;

        [GlobalSetup]
        public async Task SetupAsync()
        {
            _jsonWebTokenHandler = new JsonWebTokenHandler();
            _jwsWithExtendedClaims = _jsonWebTokenHandler.CreateToken(new SecurityTokenDescriptor
            {
                Claims = BenchmarkUtils.ClaimsExtendedExample,
                SigningCredentials = BenchmarkUtils.SigningCredentialsRsaSha256,
            });
            _tokenValidationParameters = new TokenValidationParameters()
            {
                ValidAudience = BenchmarkUtils.Audience,
                ValidateLifetime = true,
                ValidIssuer = BenchmarkUtils.Issuer,
                IssuerSigningKey = BenchmarkUtils.SigningCredentialsRsaSha256.Key,
            };
            _newTokenValidationParameters = new TokenValidationParameters()
            {
                ValidAudience = BenchmarkUtils.Audience,
                ValidateLifetime = true,
                ValidIssuer = BenchmarkUtils.Issuer,
                IssuerSigningKey = BenchmarkUtils.SigningCredentialsRsaSha256.Key,
                UseNewClaimsIdentityType = true,
            };

            _claimTypeToFind = "iss";
            _claimValueToFind = BenchmarkUtils.Issuer;
            _findPredicate = claim => claim.Type == _claimTypeToFind;
            _hasClaimPredicate = claim => claim.Type == _claimTypeToFind && claim.Value == _claimValueToFind;

            _claimsIdentity = (await _jsonWebTokenHandler.ValidateTokenAsync(_jwsWithExtendedClaims, _tokenValidationParameters).ConfigureAwait(false)).ClaimsIdentity;
            _newClaimsIdentity = (await _jsonWebTokenHandler.ValidateTokenAsync(_jwsWithExtendedClaims, _newTokenValidationParameters).ConfigureAwait(false)).ClaimsIdentity as SecurityTokenClaimsIdentity;
        }

        [Benchmark(Baseline = true), BenchmarkCategory("FindFirst")]
        public Claim ClaimsIdentity_FindFirst()
        {
            var temp = _claimsIdentity.FindFirst(_claimTypeToFind);
            return temp;
        }

        //[Benchmark(Baseline = true), BenchmarkCategory("FindFirstPredicate")]
        public Claim ClaimsIdentity_FindFirst_WithPredicate()
        {
            var temp = _claimsIdentity.FindFirst(_findPredicate);
            return temp;
        }

        [Benchmark(Baseline = true), BenchmarkCategory("FindAll")]
        public List<Claim> ClaimsIdentity_FindAll()
        {
            var temp = _claimsIdentity.FindAll(_claimTypeToFind).ToList();
            return temp;
        }

        //[Benchmark(Baseline = true), BenchmarkCategory("FindAllPredicate")]
        public List<Claim> ClaimsIdentity_FindAll_WithPredicate()
        {
            var temp = _claimsIdentity.FindAll(_findPredicate).ToList();
            return temp;
        }

        [Benchmark(Baseline = true), BenchmarkCategory("HasPayloadClaim")]
        public bool ClaimsIdentity_HasClaim()
        {
            var temp = _claimsIdentity.HasClaim(_claimTypeToFind, _claimValueToFind);
            return temp;
        }

        //[Benchmark(Baseline = true), BenchmarkCategory("HasClaimPredicate")]
        public bool ClaimsIdentity_HasClaim_WithPredicate()
        {
            var temp = _claimsIdentity.HasClaim(_hasClaimPredicate);
            return temp;
        }

        [Benchmark, BenchmarkCategory("FindFirst")]
        public Claim NewClaimsIdentity_FindFirst()
        {
            var temp = _newClaimsIdentity.FindFirst(_claimTypeToFind);
            return temp;
        }

        //[Benchmark, BenchmarkCategory("FindFirstPredicate")]
        public Claim NewClaimsIdentity_FindFirst_WithPredicate()
        {
            var temp = _newClaimsIdentity.FindFirst(_findPredicate);
            return temp;
        }

        [Benchmark, BenchmarkCategory("FindAll")]
        public List<Claim> NewClaimsIdentity_FindAll()
        {
            var temp = _newClaimsIdentity.FindAll(_claimTypeToFind).ToList();
            return temp;
        }

        //[Benchmark, BenchmarkCategory("FindAllPredicate")]
        public List<Claim> NewClaimsIdentity_FindAll_WithPredicate()
        {
            var temp = _newClaimsIdentity.FindAll(_findPredicate).ToList();
            return temp;
        }

        [Benchmark, BenchmarkCategory("HasPayloadClaim")]
        public bool NewClaimsIdentity_HasClaim()
        {
            var temp = _newClaimsIdentity.HasClaim(_claimTypeToFind, _claimValueToFind);
            return temp;
        }

        //[Benchmark, BenchmarkCategory("HasClaimPredicate")]
        public bool NewClaimsIdentity_HasClaim_WithPredicate()
        {
            var temp = _newClaimsIdentity.HasClaim(_hasClaimPredicate);
            return temp;
        }

        //[Benchmark(Baseline = true), BenchmarkCategory("ValidateAndGetClaims")]
        public async Task<IList<Claim>> ClaimsIdentity_ValidateTokenAndGetClaims()
        {
            var result = await _jsonWebTokenHandler.ValidateTokenAsync(_jwsWithExtendedClaims, _tokenValidationParameters).ConfigureAwait(false);
            var claimsIdentity = result.ClaimsIdentity;
            var claims = claimsIdentity.Claims;
            return claims.ToList();
        }

        //[Benchmark, BenchmarkCategory("ValidateAndGetClaims")]
        public async Task<IList<Claim>> NewClaimsIdentity_ValidateTokenAndGetClaims()
        {
            var result = await _jsonWebTokenHandler.ValidateTokenAsync(_jwsWithExtendedClaims, _newTokenValidationParameters).ConfigureAwait(false);
            var claimsIdentity = result.ClaimsIdentity;
            var claims = claimsIdentity.Claims;
            return claims.ToList();
        }
    }
}
