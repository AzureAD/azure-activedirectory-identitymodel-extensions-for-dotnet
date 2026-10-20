// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using Microsoft.IdentityModel.Tokens.Experimental;
using Xunit;
using static Microsoft.IdentityModel.TestUtils.ReplayIdentityTestUtilities;

namespace Microsoft.IdentityModel.Tokens.Tests
{
    public class ReplayCacheIdentityTests
    {
        [Theory]
        [InlineData(false)]
        [InlineData(true)]
        public void ReplayIdentityOptionClones(bool enabled)
        {
            // Arrange
            Assert.False(new TokenValidationParameters().UseTokenReplayCacheIdentity);
            Assert.False(new ValidationParameters().UseTokenReplayCacheIdentity);
            var current = new CopyableCurrent { UseTokenReplayCacheIdentity = enabled };
            var experimental = new CopyableExperimental { UseTokenReplayCacheIdentity = enabled };

            // Act / Assert: cloning and protected copy constructors preserve the option independently.
            Assert.Equal(enabled, current.Clone().UseTokenReplayCacheIdentity);
            Assert.Equal(enabled, experimental.Clone().UseTokenReplayCacheIdentity);
            Assert.Equal(enabled, new CopyableCurrent(current).UseTokenReplayCacheIdentity);
            Assert.Equal(enabled, new CopyableExperimental(experimental).UseTokenReplayCacheIdentity);
            current.Clone().UseTokenReplayCacheIdentity = !enabled;
            experimental.Clone().UseTokenReplayCacheIdentity = !enabled;
            Assert.Equal(enabled, current.UseTokenReplayCacheIdentity);
            Assert.Equal(enabled, experimental.UseTokenReplayCacheIdentity);
        }

        [Fact]
        public void ReplayIdentityDirectValidatorsKeepSuppliedString()
        {
            // Direct validators cannot know whether a string is a JWT, assertion, or application key.
            const string token = "application-defined-original";
            DateTime expires = DateTime.UtcNow.AddHours(1);
            var cache = new StatefulReplayCache();
            var current = new TokenValidationParameters
            {
                UseTokenReplayCacheIdentity = true, ValidateTokenReplay = true, TokenReplayCache = cache
            };
            Validators.ValidateTokenReplay(expires, token, current);
            Assert.Equal(token, Assert.Single(cache.Adds));
            Assert.Throws<SecurityTokenReplayDetectedException>(() => Validators.ValidateTokenReplay(token, expires, current));

            cache = new StatefulReplayCache();
            var experimental = new ValidationParameters { UseTokenReplayCacheIdentity = true, TokenReplayCache = cache };
            Assert.True(Validators.ValidateTokenReplay(expires, token, experimental, new CallContext()).Succeeded);
            Assert.Equal(token, Assert.Single(cache.Adds));
            var replay = Validators.ValidateTokenReplay(expires, token, experimental, new CallContext());
            Assert.False(replay.Succeeded);
            Assert.IsType<SecurityTokenReplayDetectedException>(replay.Error.GetException());
        }

        [Fact]
        public void ReplayIdentitySeparatesFormatsAndTupleBoundaries()
        {
            // No lossy concatenation or issuer normalization is permitted.
            string saml1 = TokenReplayCacheIdentity.CreateSaml("SAML1", "ab", "c");
            string saml2 = TokenReplayCacheIdentity.CreateSaml("SAML2", "ab", "c");
            Assert.NotEqual(saml1, saml2);
            Assert.NotEqual(saml1, TokenReplayCacheIdentity.CreateSaml("SAML1", "a", "bc"));
            Assert.NotEqual(saml1, TokenReplayCacheIdentity.CreateSaml("SAML1", "AB", "c"));
            Assert.NotEqual(TokenReplayCacheIdentity.CreateSaml("SAML1", "a:b", "c"),
                TokenReplayCacheIdentity.CreateSaml("SAML1", "a", "b:c"));
            Assert.NotEqual(TokenReplayCacheIdentity.CreateJwt("a.b.signature"), saml1);
            Assert.Equal(TokenReplayCacheIdentity.CreateJwt("a.b.first"), TokenReplayCacheIdentity.CreateJwt("a.b.second"));
            Assert.Equal("IM.Replay.v1._Ry8icnFeF_JsI5xJ-qiF0btRnVfcnAuPr9Gq9bBUEw", TokenReplayCacheIdentity.CreateJwt("a.b.signature"));
            Assert.NotEqual(TokenReplayCacheIdentity.CreateJwt("a.b.first"), TokenReplayCacheIdentity.CreateJwt("a.c.first"));
            Assert.NotEqual(TokenReplayCacheIdentity.CreateJwt("a.b.first"), TokenReplayCacheIdentity.CreateJwt("c.b.first"));
        }

        private sealed class CopyableCurrent : TokenValidationParameters
        {
            internal CopyableCurrent() { }
            internal CopyableCurrent(TokenValidationParameters other) : base(other) { }
        }

        private sealed class CopyableExperimental : ValidationParameters
        {
            internal CopyableExperimental() { }
            internal CopyableExperimental(ValidationParameters other) : base(other) { }
        }
    }
}
