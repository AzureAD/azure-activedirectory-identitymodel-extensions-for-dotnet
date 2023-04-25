// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Linq;
using Microsoft.IdentityModel.TestUtils;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace Microsoft.IdentityModel.JsonWebTokens.Tests
{
    public class JwtTokenUtilitiesTests
    {
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
            resolvedKey = JwtTokenUtilities.ResolveTokenSigningKeyUsingValidationParameters(testKeyId, null, tvp);
            Assert.NotNull(resolvedKey);
            Assert.Same(resolvedKey, tvp.IssuerSigningKey);

            // signingKey.KeyId matched, TVP.IssuerSigningKeys
            tvp.IssuerSigningKey = null;
            tvp.IssuerSigningKeys = new List<SecurityKey>() { signingKey };

            resolvedKey = JwtTokenUtilities.ResolveTokenSigningKeyUsingValidationParameters(testKeyId, Base64UrlEncoder.Encode(testKeyId), tvp);
            Assert.NotNull(resolvedKey);
            Assert.Same(resolvedKey, tvp.IssuerSigningKeys.First());

            #endregion

            #region X5t

            // x5t matches TVP.IssuerSigningKey as X509SecurityKey.X5t
            signingKey.KeyId = Guid.NewGuid().ToString();
            tvp.IssuerSigningKey = signingKey;
            tvp.IssuerSigningKeys = null;

            resolvedKey = JwtTokenUtilities.ResolveSigningKeyUsingKeyId(testKeyId, signingKey.X5t, tvp);
            Assert.NotNull(resolvedKey);
            Assert.Same(resolvedKey, tvp.IssuerSigningKey);

            // x5t matches TVP.IssuerSigningKeys.First() as X509SecurityKey.X5t
            signingKey.KeyId = Guid.NewGuid().ToString();
            tvp.IssuerSigningKey = null;
            tvp.IssuerSigningKeys = new List<SecurityKey>() { signingKey };

            resolvedKey = JwtTokenUtilities.ResolveSigningKeyUsingKeyId(testKeyId, signingKey.X5t, tvp);
            Assert.NotNull(resolvedKey);
            Assert.Same(resolvedKey, tvp.IssuerSigningKeys.First());

            #endregion

            // no match
            resolvedKey = JwtTokenUtilities.ResolveSigningKeyUsingKeyId(Guid.NewGuid().ToString(), Guid.NewGuid().ToString(), tvp);
            Assert.Null(resolvedKey);

            resolvedKey = JwtTokenUtilities.ResolveSigningKeyUsingKeyId(null, null, tvp);
            Assert.Null(resolvedKey);
        }
    }
}
