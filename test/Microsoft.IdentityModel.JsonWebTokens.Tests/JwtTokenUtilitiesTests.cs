// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.TestUtils;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace Microsoft.IdentityModel.JsonWebTokens.Tests
{
    public class JwtTokenUtilitiesTests
    {
        [Fact]
        public void ClaimTypeMappingIsIndependent()
        {
            // Each handler should have its own instance of the ClaimTypeMap
            var jwtClaimsMapping = JwtSecurityTokenHandler.DefaultInboundClaimTypeMap;
            var jsonClaimsMapping = JsonWebTokenHandler.DefaultInboundClaimTypeMap;

            Assert.NotEmpty(jwtClaimsMapping);
            Assert.NotEmpty(jsonClaimsMapping);

            Assert.Equal(jwtClaimsMapping, jsonClaimsMapping);

            // Clearing one should not affect the other
            jwtClaimsMapping.Clear();

            Assert.Empty(jwtClaimsMapping);
            Assert.NotEmpty(jsonClaimsMapping);

        }

        [Fact]
        public void ResolveTokenSigningKey()
        {
            var testKeyId = Guid.NewGuid().ToString();
            var tvp = new TokenValidationParameters();

            // null configuration
            var resolvedKey = JwtTokenUtilities.ResolveTokenSigningKey(testKeyId, null, tvp, null);
            Assert.Null(resolvedKey);

            // null tvp
            resolvedKey = JwtTokenUtilities.ResolveTokenSigningKey(testKeyId, null, null, null);
            Assert.Null(resolvedKey);

            var signingKey = new X509SecurityKey(KeyingMaterial.CertSelfSigned1024_SHA256);
            signingKey.KeyId = testKeyId;
            tvp.IssuerSigningKey = signingKey;

            #region KeyId

            // signingKey.KeyId matches TVP.IssuerSigningKey
            resolvedKey = JwtTokenUtilities.ResolveTokenSigningKey(testKeyId, null, tvp, null);
            Assert.NotNull(resolvedKey);
            Assert.Same(resolvedKey, tvp.IssuerSigningKey);

            // signingKey.KeyId matched, TVP.IssuerSigningKeys
            tvp.IssuerSigningKey = null;
            tvp.IssuerSigningKeys = new List<SecurityKey>() { signingKey };

            resolvedKey = JwtTokenUtilities.ResolveTokenSigningKey(testKeyId, Base64UrlEncoder.Encode(testKeyId), tvp, null);
            Assert.NotNull(resolvedKey);
            Assert.Same(resolvedKey, tvp.IssuerSigningKeys.First());

            // signingKey.KeyId matches configuration.SigningKeys.First()
            tvp.IssuerSigningKey = null;
            tvp.IssuerSigningKeys = null;
            var configuration = GetConfigurationMock();
            var testSigningKey = configuration.SigningKeys.First();

            resolvedKey = JwtTokenUtilities.ResolveTokenSigningKey(testSigningKey.KeyId, string.Empty, tvp, configuration);
            Assert.Same(resolvedKey, testSigningKey);

            #endregion

            #region X5t

            // signingKey.X5t matches TVP.IssuerSigningKey
            signingKey.KeyId = Guid.NewGuid().ToString();
            tvp.IssuerSigningKey = signingKey;
            tvp.IssuerSigningKeys = null;

            resolvedKey = JwtTokenUtilities.ResolveTokenSigningKey(testKeyId, signingKey.X5t, tvp, null);
            Assert.Same(resolvedKey, tvp.IssuerSigningKey);

            // signingKey.X5t matches tvp.IssuerSigningKey since X509SecurityKey comparison is case-insensitive
            resolvedKey = JwtTokenUtilities.ResolveTokenSigningKey(testKeyId, signingKey.X5t.ToUpper(), tvp, null);
            Assert.Same(resolvedKey, tvp.IssuerSigningKey);

            // signingKey.X5t matches TVP.IssuerSigningKeys.First()
            signingKey.KeyId = Guid.NewGuid().ToString();
            tvp.IssuerSigningKey = null;
            tvp.IssuerSigningKeys = new List<SecurityKey>() { signingKey };

            resolvedKey = JwtTokenUtilities.ResolveTokenSigningKey(testKeyId, signingKey.X5t, tvp, null);
            Assert.Same(resolvedKey, tvp.IssuerSigningKeys.First());

            // signingKey.X5t matches configuration.SigningKeys.First()
            signingKey.KeyId = Guid.NewGuid().ToString();
            tvp.IssuerSigningKey = null;
            tvp.IssuerSigningKeys = null;
            configuration = GetConfigurationMock();

            resolvedKey = JwtTokenUtilities.ResolveTokenSigningKey(testKeyId, signingKey.X5t, tvp, configuration);
            Assert.Same(resolvedKey, configuration.SigningKeys.First());

            #endregion

            // no signing key resolved
            resolvedKey = JwtTokenUtilities.ResolveTokenSigningKey(Guid.NewGuid().ToString(), Guid.NewGuid().ToString(), tvp, null);
            Assert.Null(resolvedKey);

            resolvedKey = JwtTokenUtilities.ResolveTokenSigningKey(null, null, tvp, null);
            Assert.Null(resolvedKey);

            resolvedKey = JwtTokenUtilities.ResolveTokenSigningKey(null, null, tvp, GetConfigurationNoMatchingKeyMock());
            Assert.Null(resolvedKey);
        }

        private BaseConfiguration GetConfigurationMock()
        {
            var config = new OpenIdConnectConfiguration();
            config.SigningKeys.Add(KeyingMaterial.X509SecurityKeySelfSigned1024_SHA256_Public);
            config.SigningKeys.Add(KeyingMaterial.X509SecurityKeySelfSigned2048_SHA384_Public);

            return config;
        }

        private BaseConfiguration GetConfigurationNoMatchingKeyMock()
        {
            var config = new OpenIdConnectConfiguration();
            config.SigningKeys.Add(KeyingMaterial.DefaultRsaSecurityKey1);
            config.SigningKeys.Add(KeyingMaterial.DefaultRsaSecurityKey2);

            return config;
        }
    }
}
