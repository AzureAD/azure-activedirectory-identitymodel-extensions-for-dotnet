// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace Microsoft.IdentityModel.Dpop.Tests
{
    public class DPoPProofValidatorTests
    {
        private readonly DPoPProofValidator _validator = new();

        private static RSA CreateTestRsa()
        {
#if NET462
            return new RSACryptoServiceProvider(2048);
#else
            return RSA.Create(2048);
#endif
        }

        #region Test Helpers

#if !NET462 // EC helpers for EC-specific algorithm tests only
        private static (string ProofJwt, ECDsa Key) CreateValidEcProof(
            string httpMethod = "GET",
            string uri = "https://resource.example.org/api",
            string accessToken = null,
            string nonce = DefaultTestNonce)
        {
            var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var signingCredentials = new SigningCredentials(
                new ECDsaSecurityKey(ecdsa), SecurityAlgorithms.EcdsaSha256);

            var proofOptions = new DPoPProofCreatorOptions
            {
                SigningCredentials = signingCredentials,
                IncludeNonce = !string.IsNullOrEmpty(nonce),
                Nonce = nonce,
            };
            var dpopProof = new DPoPProofCreator(proofOptions);
            var jwt = dpopProof.CreateProof(httpMethod, new Uri(uri), accessToken);
            return (jwt, ecdsa);
        }
#endif

        /// <summary>
        /// Creates a valid DPoP proof using RSA (works on all TFMs including net462).
        /// For tests that don't need to tamper with individual claims.
        /// </summary>
        private static (string ProofJwt, RSA Key) CreateValidRsaProof(
            string httpMethod = "GET",
            string uri = "https://resource.example.org/api",
            string accessToken = null,
            string nonce = DefaultTestNonce,
            RSA proofKey = null)
        {
            var rsa = proofKey ?? CreateTestRsa();
            var signingCredentials = new SigningCredentials(
                new RsaSecurityKey(rsa), SecurityAlgorithms.RsaSha256);

            var proofOptions = new DPoPProofCreatorOptions
            {
                SigningCredentials = signingCredentials,
                IncludeNonce = !string.IsNullOrEmpty(nonce),
                Nonce = nonce,
            };
            var dpopProof = new DPoPProofCreator(proofOptions);
            var jwt = dpopProof.CreateProof(httpMethod, new Uri(uri), accessToken);
            return (jwt, rsa);
        }

        /// <summary>
        /// Creates a tampered DPoP proof using RSA with specific claims omitted.
        /// Works on all TFMs including net462.
        /// </summary>
        private static (string ProofJwt, RSA Key) CreateTamperedRsaProof(
            string httpMethod = "GET",
            string uri = "https://resource.example.org/api",
            string accessToken = null,
            string nonce = DefaultTestNonce,
            string typ = "dpop+jwt",
            long? iatOverride = null,
            bool omitJti = false,
            bool omitHtm = false,
            bool omitHtu = false,
            bool omitIat = false,
            bool omitAth = false,
            bool includePrivateKey = false,
            RSA proofKey = null)
        {
            var rsa = proofKey ?? CreateTestRsa();
            var signingCredentials = new SigningCredentials(
                new RsaSecurityKey(rsa), SecurityAlgorithms.RsaSha256);

            var now = DateTimeOffset.UtcNow;
            var claims = new Dictionary<string, object>();

            if (!omitHtm)
                claims["htm"] = httpMethod.ToUpperInvariant();
            if (!omitHtu)
                claims["htu"] = new Uri(uri).GetLeftPart(UriPartial.Path);
            if (!omitIat)
                claims["iat"] = iatOverride ?? now.ToUnixTimeSeconds();
            if (!omitJti)
                claims["jti"] = Guid.NewGuid().ToString();

            if (!string.IsNullOrEmpty(accessToken) && !omitAth)
            {
#if NET6_0_OR_GREATER
                var hash = SHA256.HashData(Encoding.ASCII.GetBytes(accessToken));
#else
                byte[] hash;
                using (var sha = SHA256.Create())
                {
                    hash = sha.ComputeHash(Encoding.ASCII.GetBytes(accessToken));
                }
#endif
                claims["ath"] = Base64UrlEncoder.Encode(hash);
            }

            if (!string.IsNullOrEmpty(nonce))
                claims["nonce"] = nonce;

            // Build RSA JWK for header
            var rsaParams = rsa.ExportParameters(includePrivateKey);
            var jwkForHeader = new System.Text.Json.Nodes.JsonObject
            {
                ["e"] = Base64UrlEncoder.Encode(rsaParams.Exponent),
                ["kty"] = "RSA",
                ["n"] = Base64UrlEncoder.Encode(rsaParams.Modulus),
            };
            if (includePrivateKey)
            {
                jwkForHeader["d"] = Base64UrlEncoder.Encode(rsaParams.D);
                jwkForHeader["p"] = Base64UrlEncoder.Encode(rsaParams.P);
                jwkForHeader["q"] = Base64UrlEncoder.Encode(rsaParams.Q);
            }

            var headerClaims = new Dictionary<string, object>
            {
                { "typ", typ },
                { "jwk", jwkForHeader }
            };

            var descriptor = new SecurityTokenDescriptor
            {
                IncludeKeyIdInHeader = false,
                Claims = claims,
                AdditionalHeaderClaims = headerClaims,
                SigningCredentials = signingCredentials,
            };

            var handler = new JsonWebTokenHandler { SetDefaultTimesOnTokenCreation = false };
            var jwt = handler.CreateToken(descriptor);
            return (jwt, rsa);
        }

        private const string DefaultTestNonce = "test-server-nonce";

        private static DPoPValidationOptions DefaultOptions() => new()
        {
            AllowedSigningAlgorithms = new HashSet<string>(StringComparer.Ordinal) { "ES256", "RS256" },
            MaxLifetimeInSeconds = 300,
            ClockSkewInSeconds = 300,
            ExpectedNonce = DefaultTestNonce,
        };

        /// <summary>
        /// Creates a simple access token with a cnf.jkt claim bound to the given proof key.
        /// </summary>
        private static (string AccessToken, string CnfJkt) CreateSimpleAccessToken(RSA proofKey)
        {
            var atSigningKey = CreateTestRsa();
            var handler = new JsonWebTokenHandler();

            var jwk = JsonWebKeyConverter.ConvertFromSecurityKey(new RsaSecurityKey(proofKey));
            var thumbprint = DPoPProofValidator.ComputeJwkThumbprint(jwk);
            var cnfJson = $"{{\"jkt\":\"{thumbprint}\"}}";

            using var doc = System.Text.Json.JsonDocument.Parse(cnfJson);
            var claims = new Dictionary<string, object>
            {
                { "sub", "test" },
                { "cnf", doc.RootElement.Clone() },
            };

            var accessToken = handler.CreateToken(new SecurityTokenDescriptor
            {
                Issuer = "https://test-issuer.example.com",
                Audience = "api://test",
                Claims = claims,
                SigningCredentials = new SigningCredentials(new RsaSecurityKey(atSigningKey), SecurityAlgorithms.RsaSha256),
            });

            return (accessToken, thumbprint);
        }

        /// <summary>
        /// Creates a valid DPoP proof and a matching access token with cnf.jkt binding.
        /// </summary>
        private static (string ProofJwt, string AccessToken, string CnfJkt) CreateProofAndAccessToken(
            string httpMethod = "GET",
            string uri = "https://resource.example.org/api",
            string nonce = DefaultTestNonce)
        {
            var rsa = CreateTestRsa();
            var (at, cnfJkt) = CreateSimpleAccessToken(rsa);
            var (proofJwt, _) = CreateValidRsaProof(httpMethod, uri, accessToken: at, nonce: nonce, proofKey: rsa);
            return (proofJwt, at, cnfJkt);
        }

        /// <summary>
        /// Creates a tampered DPoP proof and a matching access token with cnf.jkt binding.
        /// </summary>
        private static (string ProofJwt, string AccessToken, string CnfJkt) CreateTamperedProofAndAccessToken(
            string httpMethod = "GET",
            string uri = "https://resource.example.org/api",
            string nonce = DefaultTestNonce,
            string typ = "dpop+jwt",
            long? iatOverride = null,
            bool omitJti = false,
            bool omitHtm = false,
            bool omitHtu = false,
            bool omitIat = false,
            bool omitAth = false,
            bool includePrivateKey = false)
        {
            var rsa = CreateTestRsa();
            var (at, cnfJkt) = CreateSimpleAccessToken(rsa);
            var (proofJwt, _) = CreateTamperedRsaProof(
                httpMethod, uri, accessToken: at, nonce: nonce, typ: typ,
                iatOverride: iatOverride, omitJti: omitJti, omitHtm: omitHtm,
                omitHtu: omitHtu, omitIat: omitIat, omitAth: omitAth,
                includePrivateKey: includePrivateKey, proofKey: rsa);
            return (proofJwt, at, cnfJkt);
        }

        #endregion

        #region Happy Path

        [Fact]
        public async Task ValidateAsync_ValidProof_Succeeds()
        {
            var (proof, accessToken, cnfJkt) = CreateProofAndAccessToken();
            var options = DefaultOptions();

            var result = await _validator.ValidateAsync(
                proof, "GET", new Uri("https://resource.example.org/api"), accessToken, cnfJkt, options);

            Assert.True(result.IsValid);
            Assert.Null(result.Exception);
            Assert.False(result.IsNonceRequired);
        }

        [Fact]
        public async Task ValidateAsync_ValidProofWithAccessToken_Succeeds()
        {
            var (proof, accessToken, cnfJkt) = CreateProofAndAccessToken();
            var options = DefaultOptions();

            var result = await _validator.ValidateAsync(
                proof, "GET", new Uri("https://resource.example.org/api"), accessToken, cnfJkt, options);

            Assert.True(result.IsValid);
        }

        [Fact]
        public async Task ValidateAsync_ValidProofWithNonce_Succeeds()
        {
            var (proof, accessToken, cnfJkt) = CreateProofAndAccessToken(nonce: "server-nonce-42");
            var options = DefaultOptions();
            options.ExpectedNonce = "server-nonce-42";

            var result = await _validator.ValidateAsync(
                proof, "GET", new Uri("https://resource.example.org/api"), accessToken, cnfJkt, options);

            Assert.True(result.IsValid);
        }

        [Fact]
        public async Task ValidateAsync_PostMethod_Succeeds()
        {
            var (proof, accessToken, cnfJkt) = CreateProofAndAccessToken(httpMethod: "POST");
            var options = DefaultOptions();

            var result = await _validator.ValidateAsync(
                proof, "POST", new Uri("https://resource.example.org/api"), accessToken, cnfJkt, options);

            Assert.True(result.IsValid);
        }

        #endregion

        #region Typ Validation

        [Fact]
        public async Task ValidateAsync_WrongTyp_Fails()
        {
            var (proof, accessToken, cnfJkt) = CreateTamperedProofAndAccessToken(typ: "jwt");
            var options = DefaultOptions();

            var result = await _validator.ValidateAsync(
                proof, "GET", new Uri("https://resource.example.org/api"), accessToken, cnfJkt, options);

            Assert.False(result.IsValid);
            Assert.Contains("typ", result.Error);
        }

        #endregion

        #region Algorithm Validation

        [Fact]
        public async Task ValidateAsync_AlgorithmNotInAllowedSet_Fails()
        {
            var (proof, accessToken, cnfJkt) = CreateProofAndAccessToken();
            var options = DefaultOptions();
            options.AllowedSigningAlgorithms = new HashSet<string>(StringComparer.Ordinal) { "PS256" };

            var result = await _validator.ValidateAsync(
                proof, "GET", new Uri("https://resource.example.org/api"), accessToken, cnfJkt, options);

            Assert.False(result.IsValid);
            Assert.Contains("not in the allowed set", result.Error);
        }

        [Fact]
        public async Task ValidateAsync_AlgNone_Fails()
        {
            var header = Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes("{\"typ\":\"dpop+jwt\",\"alg\":\"none\",\"jwk\":{\"kty\":\"RSA\",\"e\":\"AQAB\",\"n\":\"test\"}}"));
            var payload = Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes("{\"htm\":\"GET\",\"htu\":\"https://example.com\",\"iat\":1704063600,\"jti\":\"test\"}"));
            var fakeProof = $"{header}.{payload}.";

            var rsa = CreateTestRsa();
            var (accessToken, cnfJkt) = CreateSimpleAccessToken(rsa);

            var result = await _validator.ValidateAsync(
                fakeProof, "GET", new Uri("https://example.com"), accessToken, cnfJkt, DefaultOptions());

            Assert.False(result.IsValid);
            Assert.Contains("none", result.Error);
        }

        [Fact]
        public async Task ValidateAsync_SymmetricAlgorithm_Fails()
        {
            var header = Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes("{\"typ\":\"dpop+jwt\",\"alg\":\"HS256\",\"jwk\":{\"kty\":\"RSA\",\"e\":\"AQAB\",\"n\":\"test\"}}"));
            var payload = Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes("{\"htm\":\"GET\",\"htu\":\"https://example.com\",\"iat\":1704063600,\"jti\":\"test\"}"));
            var fakeProof = $"{header}.{payload}.fakesig";

            var rsa = CreateTestRsa();
            var (accessToken, cnfJkt) = CreateSimpleAccessToken(rsa);

            var result = await _validator.ValidateAsync(
                fakeProof, "GET", new Uri("https://example.com"), accessToken, cnfJkt, DefaultOptions());

            Assert.False(result.IsValid);
            Assert.Contains("asymmetric", result.Error);
        }

        [Fact]
        public async Task ValidateAsync_EmptyAlg_Fails()
        {
            var header = Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes("{\"typ\":\"dpop+jwt\",\"alg\":\"\",\"jwk\":{\"kty\":\"RSA\",\"e\":\"AQAB\",\"n\":\"test\"}}"));
            var payload = Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes("{\"htm\":\"GET\",\"htu\":\"https://example.com\",\"iat\":" + DateTimeOffset.UtcNow.ToUnixTimeSeconds() + ",\"jti\":\"test\"}"));
            var fakeProof = $"{header}.{payload}.fakesig";

            var rsa = CreateTestRsa();
            var (accessToken, cnfJkt) = CreateSimpleAccessToken(rsa);

            var result = await _validator.ValidateAsync(
                fakeProof, "GET", new Uri("https://example.com"), accessToken, cnfJkt, DefaultOptions());

            Assert.False(result.IsValid);
            Assert.Contains("empty", result.Error, StringComparison.OrdinalIgnoreCase);
        }

        [Fact]
        public async Task ValidateAsync_NullAllowedAlgorithms_Fails()
        {
            var (proof, accessToken, cnfJkt) = CreateProofAndAccessToken();
            var options = DefaultOptions();
            options.AllowedSigningAlgorithms = null;

            var result = await _validator.ValidateAsync(
                proof, "GET", new Uri("https://resource.example.org/api"), accessToken, cnfJkt, options);

            Assert.False(result.IsValid);
            Assert.Contains("allowed algorithm", result.Error, StringComparison.OrdinalIgnoreCase);
        }

        [Fact]
        public async Task ValidateAsync_EmptyAllowedAlgorithms_Fails()
        {
            var (proof, accessToken, cnfJkt) = CreateProofAndAccessToken();
            var options = DefaultOptions();
            options.AllowedSigningAlgorithms = new HashSet<string>();

            var result = await _validator.ValidateAsync(
                proof, "GET", new Uri("https://resource.example.org/api"), accessToken, cnfJkt, options);

            Assert.False(result.IsValid);
            Assert.Contains("allowed algorithm", result.Error, StringComparison.OrdinalIgnoreCase);
        }

        #endregion

        #region JWK Validation

        [Fact]
        public async Task ValidateAsync_MissingJwk_Fails()
        {
            var rsa = CreateTestRsa();
            var signingCredentials = new SigningCredentials(new RsaSecurityKey(rsa), SecurityAlgorithms.RsaSha256);

            var handler = new JsonWebTokenHandler { SetDefaultTimesOnTokenCreation = false };
            var jwt = handler.CreateToken(new SecurityTokenDescriptor
            {
                IncludeKeyIdInHeader = false,
                Claims = new Dictionary<string, object>
                {
                    { "htm", "GET" },
                    { "htu", "https://example.com" },
                    { "iat", DateTimeOffset.UtcNow.ToUnixTimeSeconds() },
                    { "jti", Guid.NewGuid().ToString() },
                },
                AdditionalHeaderClaims = new Dictionary<string, object>
                {
                    { "typ", "dpop+jwt" },
                },
                SigningCredentials = signingCredentials,
            });

            var (accessToken, cnfJkt) = CreateSimpleAccessToken(rsa);

            var result = await _validator.ValidateAsync(
                jwt, "GET", new Uri("https://example.com"), accessToken, cnfJkt, DefaultOptions());

            Assert.False(result.IsValid);
            Assert.Contains("jwk", result.Error);
        }

        #endregion

        #region Htm Validation

        [Fact]
        public async Task ValidateAsync_HtmMismatch_Fails()
        {
            var (proof, accessToken, cnfJkt) = CreateProofAndAccessToken(httpMethod: "POST");
            var options = DefaultOptions();

            var result = await _validator.ValidateAsync(
                proof, "GET", new Uri("https://resource.example.org/api"), accessToken, cnfJkt, options);

            Assert.False(result.IsValid);
            Assert.Contains("htm", result.Error);
        }

        [Fact]
        public async Task ValidateAsync_MissingHtm_Fails()
        {
            var (proof, accessToken, cnfJkt) = CreateTamperedProofAndAccessToken(omitHtm: true);
            var options = DefaultOptions();

            var result = await _validator.ValidateAsync(
                proof, "GET", new Uri("https://resource.example.org/api"), accessToken, cnfJkt, options);

            Assert.False(result.IsValid);
            Assert.Contains("htm", result.Error);
        }

        #endregion

        #region Htu Validation

        [Fact]
        public async Task ValidateAsync_HtuMismatch_Fails()
        {
            var (proof, accessToken, cnfJkt) = CreateProofAndAccessToken(uri: "https://resource.example.org/api");
            var options = DefaultOptions();

            var result = await _validator.ValidateAsync(
                proof, "GET", new Uri("https://other.example.org/api"), accessToken, cnfJkt, options);

            Assert.False(result.IsValid);
            Assert.Contains("htu", result.Error);
        }

        [Fact]
        public async Task ValidateAsync_MissingHtu_Fails()
        {
            var (proof, accessToken, cnfJkt) = CreateTamperedProofAndAccessToken(omitHtu: true);
            var options = DefaultOptions();

            var result = await _validator.ValidateAsync(
                proof, "GET", new Uri("https://resource.example.org/api"), accessToken, cnfJkt, options);

            Assert.False(result.IsValid);
            Assert.Contains("htu", result.Error);
        }

        [Fact]
        public async Task ValidateAsync_HtuIgnoresQueryString_Succeeds()
        {
            var (proof, accessToken, cnfJkt) = CreateProofAndAccessToken(uri: "https://resource.example.org/api?foo=bar");
            var options = DefaultOptions();

            var result = await _validator.ValidateAsync(
                proof, "GET", new Uri("https://resource.example.org/api?other=val"), accessToken, cnfJkt, options);

            Assert.True(result.IsValid);
        }

        #endregion

        #region Iat Validation

        [Fact]
        public async Task ValidateAsync_ExpiredProof_Fails()
        {
            var old = DateTimeOffset.UtcNow.AddSeconds(-700).ToUnixTimeSeconds();
            var (proof, accessToken, cnfJkt) = CreateTamperedProofAndAccessToken(iatOverride: old);
            var options = DefaultOptions();
            options.MaxLifetimeInSeconds = 60;
            options.ClockSkewInSeconds = 30;

            var result = await _validator.ValidateAsync(
                proof, "GET", new Uri("https://resource.example.org/api"), accessToken, cnfJkt, options);

            Assert.False(result.IsValid);
            Assert.Contains("expired", result.Error);
        }

        [Fact]
        public async Task ValidateAsync_FutureIat_Fails()
        {
            var future = DateTimeOffset.UtcNow.AddSeconds(700).ToUnixTimeSeconds();
            var (proof, accessToken, cnfJkt) = CreateTamperedProofAndAccessToken(iatOverride: future);
            var options = DefaultOptions();

            var result = await _validator.ValidateAsync(
                proof, "GET", new Uri("https://resource.example.org/api"), accessToken, cnfJkt, options);

            Assert.False(result.IsValid);
            Assert.Contains("future", result.Error);
        }

        [Fact]
        public async Task ValidateAsync_MissingIat_Fails()
        {
            var (proof, accessToken, cnfJkt) = CreateTamperedProofAndAccessToken(omitIat: true);
            var options = DefaultOptions();

            var result = await _validator.ValidateAsync(
                proof, "GET", new Uri("https://resource.example.org/api"), accessToken, cnfJkt, options);

            Assert.False(result.IsValid);
            Assert.Contains("iat", result.Error);
        }

        #endregion

        #region Jti Validation

        [Fact]
        public async Task ValidateAsync_MissingJti_Fails()
        {
            var (proof, accessToken, cnfJkt) = CreateTamperedProofAndAccessToken(omitJti: true);
            var options = DefaultOptions();

            var result = await _validator.ValidateAsync(
                proof, "GET", new Uri("https://resource.example.org/api"), accessToken, cnfJkt, options);

            Assert.False(result.IsValid);
            Assert.Contains("jti", result.Error);
        }

        [Fact]
        public async Task ValidateAsync_JtiReplayDetected_Fails()
        {
            var (proof, accessToken, cnfJkt) = CreateProofAndAccessToken();
            var cache = new TestJtiReplayCache(replayDetected: true);
            var options = DefaultOptions();
            options.JtiReplayCache = cache;

            var result = await _validator.ValidateAsync(
                proof, "GET", new Uri("https://resource.example.org/api"), accessToken, cnfJkt, options);

            Assert.False(result.IsValid);
            Assert.Contains("replay", result.Error);
            Assert.True(cache.WasCalled);
        }

        [Fact]
        public async Task ValidateAsync_JtiFirstUse_Succeeds()
        {
            var (proof, accessToken, cnfJkt) = CreateProofAndAccessToken();
            var cache = new TestJtiReplayCache(replayDetected: false);
            var options = DefaultOptions();
            options.JtiReplayCache = cache;

            var result = await _validator.ValidateAsync(
                proof, "GET", new Uri("https://resource.example.org/api"), accessToken, cnfJkt, options);

            Assert.True(result.IsValid);
            Assert.True(cache.WasCalled);
        }

        [Fact]
        public async Task ValidateAsync_NoCacheConfigured_SkipsJtiCheck()
        {
            var (proof, accessToken, cnfJkt) = CreateProofAndAccessToken();
            var options = DefaultOptions();
            options.JtiReplayCache = null;

            var result = await _validator.ValidateAsync(
                proof, "GET", new Uri("https://resource.example.org/api"), accessToken, cnfJkt, options);

            Assert.True(result.IsValid);
        }

        [Fact]
        public async Task ValidateAsync_NeitherJtiNorNonce_StillSucceeds_IatProvidesBaseline()
        {
            var (proof, accessToken, cnfJkt) = CreateProofAndAccessToken(nonce: null);
            var options = DefaultOptions();
            options.JtiReplayCache = null;
            options.ExpectedNonce = null;

            var result = await _validator.ValidateAsync(
                proof, "GET", new Uri("https://resource.example.org/api"), accessToken, cnfJkt, options);

            // Succeeds — iat freshness (step 7) provides baseline replay protection
            Assert.True(result.IsValid);
        }

        #endregion

        #region Nonce Validation

        [Fact]
        public async Task ValidateAsync_NonceMissing_ReturnsNonceRequired()
        {
            var (proof, accessToken, cnfJkt) = CreateProofAndAccessToken(nonce: null);
            var options = DefaultOptions();
            options.ExpectedNonce = "required-nonce";

            var result = await _validator.ValidateAsync(
                proof, "GET", new Uri("https://resource.example.org/api"), accessToken, cnfJkt, options);

            Assert.False(result.IsValid);
            Assert.True(result.IsNonceRequired);
        }

        [Fact]
        public async Task ValidateAsync_NonceWrong_ReturnsNonceRequired()
        {
            var (proof, accessToken, cnfJkt) = CreateProofAndAccessToken(nonce: "wrong-nonce");
            var options = DefaultOptions();
            options.ExpectedNonce = "expected-nonce";

            var result = await _validator.ValidateAsync(
                proof, "GET", new Uri("https://resource.example.org/api"), accessToken, cnfJkt, options);

            Assert.False(result.IsValid);
            Assert.True(result.IsNonceRequired);
        }

        [Fact]
        public async Task ValidateAsync_NonceNotRequired_JtiUsedInstead_Succeeds()
        {
            var (proof, accessToken, cnfJkt) = CreateProofAndAccessToken(nonce: null);
            var cache = new TestJtiReplayCache(replayDetected: false);
            var options = DefaultOptions();
            options.ExpectedNonce = null;
            options.JtiReplayCache = cache;

            var result = await _validator.ValidateAsync(
                proof, "GET", new Uri("https://resource.example.org/api"), accessToken, cnfJkt, options);

            Assert.True(result.IsValid);
        }

        [Fact]
        public async Task ValidateAsync_EmptyExpectedNonce_ReturnsInvalid()
        {
            var (proofJwt, accessToken, cnfJkt) = CreateProofAndAccessToken();
            var options = DefaultOptions();
            options.ExpectedNonce = "";

            var result = await _validator.ValidateAsync(
                proofJwt, "GET", new Uri("https://resource.example.org/api"), accessToken, cnfJkt, options);

            Assert.False(result.IsValid);
            Assert.Contains("ExpectedNonce", result.Error);
        }

        #endregion

        #region Ath (Access Token Hash) Validation

        [Fact]
        public async Task ValidateAsync_AthMismatch_Fails()
        {
            // Create proof bound to one AT, validate with a different AT
            var rsa = CreateTestRsa();
            var (atA, cnfJkt) = CreateSimpleAccessToken(rsa);
            var (atB, _) = CreateSimpleAccessToken(rsa);
            var (proof, _) = CreateValidRsaProof(accessToken: atA, proofKey: rsa);
            var options = DefaultOptions();

            var result = await _validator.ValidateAsync(
                proof, "GET", new Uri("https://resource.example.org/api"), atB, cnfJkt, options);

            Assert.False(result.IsValid);
            Assert.Contains("ath", result.Error);
        }

        [Fact]
        public async Task ValidateAsync_AthMissing_Fails()
        {
            // Create proof without ath but with a valid access token
            var (proof, accessToken, cnfJkt) = CreateTamperedProofAndAccessToken(omitAth: true);
            var options = DefaultOptions();

            var result = await _validator.ValidateAsync(
                proof, "GET", new Uri("https://resource.example.org/api"), accessToken, cnfJkt, options);

            Assert.False(result.IsValid);
            Assert.Contains("ath", result.Error);
        }

        #endregion

        #region Signature Validation

        [Fact]
        public async Task ValidateAsync_WrongSignatureKey_Fails()
        {
            var (proof, accessToken, cnfJkt) = CreateProofAndAccessToken();

            // Tamper: decode, modify a character, re-encode — signature no longer matches
            var parts = proof.Split('.');
            var payload = parts[1] + "X";
            var tampered = parts[0] + "." + payload + "." + parts[2];

            var options = DefaultOptions();

            var result = await _validator.ValidateAsync(
                tampered, "GET", new Uri("https://resource.example.org/api"), accessToken, cnfJkt, options);

            Assert.False(result.IsValid);
        }

        #endregion

        #region Private Key Detection

        [Fact]
        public void ContainsPrivateKeyMaterial_RsaPrivate_ReturnsTrue()
        {
            var jwk = new JsonWebKey { D = "secret", Kty = "RSA" };
            Assert.True(DPoPProofValidator.ContainsPrivateKeyMaterial(jwk));
        }

        [Fact]
        public void ContainsPrivateKeyMaterial_EcPublic_ReturnsFalse()
        {
            var jwk = new JsonWebKey { Kty = "EC", Crv = "P-256", X = "x", Y = "y" };
            Assert.False(DPoPProofValidator.ContainsPrivateKeyMaterial(jwk));
        }

        [Fact]
        public void ContainsPrivateKeyMaterial_RsaPublic_ReturnsFalse()
        {
            var jwk = new JsonWebKey { Kty = "RSA", E = "AQAB", N = "n" };
            Assert.False(DPoPProofValidator.ContainsPrivateKeyMaterial(jwk));
        }

        [Fact]
        public void ContainsPrivateKeyMaterial_WithDP_ReturnsTrue()
        {
            var jwk = new JsonWebKey { DP = "dp" };
            Assert.True(DPoPProofValidator.ContainsPrivateKeyMaterial(jwk));
        }

        #endregion

        #region CnfJkt Binding

        [Fact]
        public async Task ValidateAsync_CnfJktMatch_Succeeds()
        {
            var (proof, accessToken, cnfJkt) = CreateProofAndAccessToken();
            var options = DefaultOptions();

            var result = await _validator.ValidateAsync(
                proof, "GET", new Uri("https://resource.example.org/api"), accessToken, cnfJkt, options);

            Assert.True(result.IsValid);
        }

        [Fact]
        public async Task ValidateAsync_CnfJktMismatch_Fails()
        {
            var (proof, accessToken, _) = CreateProofAndAccessToken();
            var options = DefaultOptions();

            var result = await _validator.ValidateAsync(
                proof, "GET", new Uri("https://resource.example.org/api"), accessToken, "wrong-thumbprint", options);

            Assert.False(result.IsValid);
            Assert.Contains("cnf.jkt", result.Error);
        }

        [Fact]
        public async Task ValidateAsync_EmptyCnfJkt_ReturnsInvalid()
        {
            var (proof, accessToken, _) = CreateProofAndAccessToken();
            var options = DefaultOptions();

            var result = await _validator.ValidateAsync(
                proof, "GET", new Uri("https://resource.example.org/api"), accessToken, " ", options);

            Assert.False(result.IsValid);
            Assert.Contains("cnf.jkt", result.Error);
        }

        #endregion

        #region ComputeAccessTokenHash

        [Fact]
        public void ComputeAccessTokenHash_Deterministic()
        {
            var hash1 = DPoPProofValidator.ComputeAccessTokenHash("my-token");
            var hash2 = DPoPProofValidator.ComputeAccessTokenHash("my-token");
            Assert.Equal(hash1, hash2);
        }

        [Fact]
        public void ComputeAccessTokenHash_DifferentTokens_DifferentHash()
        {
            var hash1 = DPoPProofValidator.ComputeAccessTokenHash("token-A");
            var hash2 = DPoPProofValidator.ComputeAccessTokenHash("token-B");
            Assert.NotEqual(hash1, hash2);
        }

        #endregion

        #region JwkThumbprint

#if !NET462 // net462 lacks ECDsa.Create(ECCurve) and ECDsa.ExportParameters
        [Fact]
        public void ComputeJwkThumbprint_EC_Deterministic()
        {
            var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var jwk = JsonWebKeyConverter.ConvertFromSecurityKey(new ECDsaSecurityKey(ecdsa));

            var t1 = DPoPProofValidator.ComputeJwkThumbprint(jwk);
            var t2 = DPoPProofValidator.ComputeJwkThumbprint(jwk);
            Assert.Equal(t1, t2);
            Assert.False(string.IsNullOrEmpty(t1));
        }
#endif

        [Fact]
        public void ComputeJwkThumbprint_RSA_Deterministic()
        {
            var rsa = CreateTestRsa();
            var jwk = JsonWebKeyConverter.ConvertFromSecurityKey(new RsaSecurityKey(rsa));

            var t1 = DPoPProofValidator.ComputeJwkThumbprint(jwk);
            var t2 = DPoPProofValidator.ComputeJwkThumbprint(jwk);
            Assert.Equal(t1, t2);
        }

        #endregion

        #region Input Validation

        [Fact]
        public async Task ValidateAsync_NullProof_Throws()
        {
            await Assert.ThrowsAsync<ArgumentNullException>(() =>
                _validator.ValidateAsync(null, "GET", new Uri("https://example.com"), "at", "jkt", DefaultOptions()));
        }

        [Fact]
        public async Task ValidateAsync_EmptyProof_ReturnsInvalid()
        {
            var result = await _validator.ValidateAsync(
                "  ", "GET", new Uri("https://example.com"), "at", "jkt", DefaultOptions());

            Assert.False(result.IsValid);
        }

        [Fact]
        public async Task ValidateAsync_NullOptions_Throws()
        {
            await Assert.ThrowsAsync<ArgumentNullException>(() =>
                _validator.ValidateAsync("jwt", "GET", new Uri("https://example.com"), "at", "jkt", null));
        }

        [Fact]
        public async Task ValidateAsync_NullAccessToken_Throws()
        {
            await Assert.ThrowsAsync<ArgumentNullException>(() =>
                _validator.ValidateAsync("jwt", "GET", new Uri("https://example.com"), null, "jkt", DefaultOptions()));
        }

        [Fact]
        public async Task ValidateAsync_NullCnfJkt_Throws()
        {
            await Assert.ThrowsAsync<ArgumentNullException>(() =>
                _validator.ValidateAsync("jwt", "GET", new Uri("https://example.com"), "at", null, DefaultOptions()));
        }

        [Fact]
        public async Task ValidateAsync_EmptyAccessToken_ReturnsInvalid()
        {
            var result = await _validator.ValidateAsync(
                "jwt", "GET", new Uri("https://example.com"), " ", "jkt", DefaultOptions());

            Assert.False(result.IsValid);
            Assert.Contains("Access token", result.Error);
        }

        [Fact]
        public async Task ValidateAsync_RelativeUri_Throws()
        {
            await Assert.ThrowsAsync<ArgumentException>(() =>
                _validator.ValidateAsync("jwt", "GET", new Uri("/relative", UriKind.Relative), "at", "jkt", DefaultOptions()));
        }

        [Fact]
        public async Task ValidateAsync_UnparseableProof_ReturnsInvalid()
        {
            var rsa = CreateTestRsa();
            var (accessToken, cnfJkt) = CreateSimpleAccessToken(rsa);

            var result = await _validator.ValidateAsync(
                "not-a-jwt", "GET", new Uri("https://example.com/api"), accessToken, cnfJkt, DefaultOptions());

            Assert.False(result.IsValid);
            Assert.NotNull(result.Exception);
        }

        #endregion

        #region RSA Key Support

        [Fact]
        public async Task ValidateAsync_RsaKey_Succeeds()
        {
            var rsa = CreateTestRsa();
            var (accessToken, cnfJkt) = CreateSimpleAccessToken(rsa);
            var signingCredentials = new SigningCredentials(
                new RsaSecurityKey(rsa), SecurityAlgorithms.RsaSha256);

            var proofOptions = new DPoPProofCreatorOptions
            {
                SigningCredentials = signingCredentials,
                IncludeNonce = true,
                Nonce = DefaultTestNonce,
            };
            var dpopProof = new DPoPProofCreator(proofOptions);
            var proof = dpopProof.CreateProof("GET", new Uri("https://resource.example.org/api"), accessToken);

            var options = new DPoPValidationOptions
            {
                AllowedSigningAlgorithms = new HashSet<string>(StringComparer.Ordinal) { "RS256" },
                ExpectedNonce = DefaultTestNonce,
            };

            var result = await _validator.ValidateAsync(
                proof, "GET", new Uri("https://resource.example.org/api"), accessToken, cnfJkt, options);

            Assert.True(result.IsValid);
        }

        #endregion

        #region Test Doubles

        /// <summary>
        /// Simple test double for <see cref="IJtiReplayCache"/>.
        /// </summary>
        private sealed class TestJtiReplayCache : IJtiReplayCache
        {
            private readonly bool _replayDetected;

            public TestJtiReplayCache(bool replayDetected)
            {
                _replayDetected = replayDetected;
            }

            public bool WasCalled { get; private set; }

            public Task<bool> TryAddAsync(string jti, DateTimeOffset expiration, CancellationToken cancellationToken = default)
            {
                WasCalled = true;
                // TryAdd returns true when added (NOT replay), false when replay detected
                return Task.FromResult(!_replayDetected);
            }
        }

        #endregion
    }
}