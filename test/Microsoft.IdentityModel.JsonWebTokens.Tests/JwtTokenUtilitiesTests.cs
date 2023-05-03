// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Diagnostics.Tracing;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.TestUtils;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace Microsoft.IdentityModel.JsonWebTokens.Tests
{
    public class JwtTokenUtilitiesTests
    {
        // Used for formatting a message for testing with one parameter.
        private const string TestMessageOneParam = "This is the parameter: '{0}'.";

        [Fact]
        public void LogExceptionsWithStringJwe_JsonWebTokenHandler()
        {
            SampleListener listener = new SampleListener();
            IdentityModelEventSource.ShowPII = false;
            IdentityModelEventSource.Logger.LogLevel = EventLevel.Error;
            listener.EnableEvents(IdentityModelEventSource.Logger, EventLevel.Error);

            var jweTokenDescriptor = new SecurityTokenDescriptor
            {
                SigningCredentials = KeyingMaterial.JsonWebKeyRsa256SigningCredentials,
                EncryptingCredentials = KeyingMaterial.DefaultSymmetricEncryptingCreds_Aes256_Sha512_512,
                Claims = Default.PayloadDictionary
            };

            string jwe = new JsonWebTokenHandler().CreateToken(jweTokenDescriptor);

            // LogExceptionMessage should not log the jwe since ShowPII is false.
            LogHelper.LogExceptionMessage(new SecurityTokenException(LogHelper.FormatInvariant(TestMessageOneParam, LogHelper.MarkAsSecurityArtifact(jwe, JwtTokenUtilities.SafeLogJwtToken))));
            Assert.DoesNotContain(jwe, listener.TraceBuffer);

            // LogExceptionMessage should log the disarmed jwe since ShowPII is true.
            IdentityModelEventSource.ShowPII = true;
            LogHelper.LogExceptionMessage(new SecurityTokenException(LogHelper.FormatInvariant(TestMessageOneParam, LogHelper.MarkAsSecurityArtifact(jwe, JwtTokenUtilities.SafeLogJwtToken))));
            Assert.Contains(jwe.Substring(0, jwe.LastIndexOf(".")), listener.TraceBuffer);
            Assert.DoesNotContain(jwe.Substring(jwe.LastIndexOf(".")), listener.TraceBuffer);

            // LogExceptionMessage should log the jwe since CompleteSecurityArtifact is true.
            IdentityModelEventSource.LogCompleteSecurityArtifact = true;
            LogHelper.LogExceptionMessage(new SecurityTokenException(LogHelper.FormatInvariant(TestMessageOneParam, LogHelper.MarkAsSecurityArtifact(jwe, JwtTokenUtilities.SafeLogJwtToken))));
            Assert.Contains(jwe, listener.TraceBuffer);
        }

        [Fact]
        public void LogExceptionsWithJwe_JsonWebTokenHandler()
        {
            SampleListener listener = new SampleListener();
            IdentityModelEventSource.ShowPII = false;
            IdentityModelEventSource.Logger.LogLevel = EventLevel.Error;
            listener.EnableEvents(IdentityModelEventSource.Logger, EventLevel.Error);

            var jweTokenDescriptor = new SecurityTokenDescriptor
            {
                SigningCredentials = KeyingMaterial.JsonWebKeyRsa256SigningCredentials,
                EncryptingCredentials = KeyingMaterial.DefaultSymmetricEncryptingCreds_Aes256_Sha512_512,
                Claims = Default.PayloadDictionary
            };

            JsonWebToken jwe = new JsonWebToken(new JsonWebTokenHandler().CreateToken(jweTokenDescriptor));

            // LogExceptionMessage should not log the jwe since ShowPII is false.
            LogHelper.LogExceptionMessage(new SecurityTokenException(LogHelper.FormatInvariant(TestMessageOneParam, jwe)));
            Assert.DoesNotContain(jwe.EncodedToken, listener.TraceBuffer);

            // LogExceptionMessage should log the disarmed jwe since ShowPII is true.
            IdentityModelEventSource.ShowPII = true;
            LogHelper.LogExceptionMessage(new SecurityTokenException(LogHelper.FormatInvariant(TestMessageOneParam, jwe)));
            Assert.Contains(jwe.EncodedToken.Substring(0, jwe.EncodedToken.LastIndexOf(".")), listener.TraceBuffer);
            Assert.DoesNotContain(jwe.AuthenticationTag, listener.TraceBuffer);

            // LogExceptionMessage should log the jwe since CompleteSecurityArtifact is true.
            IdentityModelEventSource.LogCompleteSecurityArtifact = true;
            LogHelper.LogExceptionMessage(new SecurityTokenException(LogHelper.FormatInvariant(TestMessageOneParam, jwe)));
            Assert.Contains(jwe.EncodedToken, listener.TraceBuffer);
        }

        [Fact]
        public void LogExceptionsWithStringJws_JsonWebTokenHandler()
        {
            SampleListener listener = new SampleListener();
            IdentityModelEventSource.ShowPII = false;
            IdentityModelEventSource.Logger.LogLevel = EventLevel.Error;
            listener.EnableEvents(IdentityModelEventSource.Logger, EventLevel.Error);

            var jwsTokenDescriptor = new SecurityTokenDescriptor
            {
                SigningCredentials = KeyingMaterial.JsonWebKeyRsa256SigningCredentials,
                Subject = new ClaimsIdentity(Default.PayloadClaims)
            };

            string jws = new JsonWebTokenHandler().CreateToken(jwsTokenDescriptor);

            // LogExceptionMessage should not log the jws since ShowPII is false.
            LogHelper.LogExceptionMessage(new SecurityTokenException(LogHelper.FormatInvariant(TestMessageOneParam, LogHelper.MarkAsSecurityArtifact(jws, JwtTokenUtilities.SafeLogJwtToken))));
            Assert.DoesNotContain(jws, listener.TraceBuffer);

            // LogExceptionMessage should log the disarmed jws since ShowPII is true.
            IdentityModelEventSource.ShowPII = true;
            LogHelper.LogExceptionMessage(new SecurityTokenException(LogHelper.FormatInvariant(TestMessageOneParam, LogHelper.MarkAsSecurityArtifact(jws, JwtTokenUtilities.SafeLogJwtToken))));
            Assert.Contains(jws.Substring(0, jws.LastIndexOf(".")), listener.TraceBuffer);
            Assert.DoesNotContain(jws.Substring(jws.LastIndexOf(".")), listener.TraceBuffer);

            // LogExceptionMessage should log the jws since CompleteSecurityArtifact is true.
            IdentityModelEventSource.LogCompleteSecurityArtifact = true;
            LogHelper.LogExceptionMessage(new SecurityTokenException(LogHelper.FormatInvariant(TestMessageOneParam, LogHelper.MarkAsSecurityArtifact(jws, JwtTokenUtilities.SafeLogJwtToken))));
            Assert.Contains(jws, listener.TraceBuffer);
        }

        [Fact]
        public void LogExceptionsWithJws_JsonWebTokenHandler()
        {
            SampleListener listener = new SampleListener();
            IdentityModelEventSource.ShowPII = false;
            IdentityModelEventSource.Logger.LogLevel = EventLevel.Error;
            listener.EnableEvents(IdentityModelEventSource.Logger, EventLevel.Error);

            var jwsTokenDescriptor = new SecurityTokenDescriptor
            {
                SigningCredentials = KeyingMaterial.JsonWebKeyRsa256SigningCredentials,
                Subject = new ClaimsIdentity(Default.PayloadClaims)
            };

            JsonWebToken jws = new JsonWebToken(new JsonWebTokenHandler().CreateToken(jwsTokenDescriptor));

            // LogExceptionMessage should not log the jws since ShowPII is false.
            LogHelper.LogExceptionMessage(new SecurityTokenException(LogHelper.FormatInvariant(TestMessageOneParam, jws)));
            Assert.DoesNotContain(jws.EncodedToken, listener.TraceBuffer);

            // LogExceptionMessage should log the disarmed jws since ShowPII is true.
            IdentityModelEventSource.ShowPII = true;
            LogHelper.LogExceptionMessage(new SecurityTokenException(LogHelper.FormatInvariant(TestMessageOneParam, jws)));
            Assert.Contains(jws.EncodedToken.Substring(0, jws.EncodedToken.LastIndexOf(".")), listener.TraceBuffer);
            Assert.DoesNotContain(jws.EncodedSignature, listener.TraceBuffer);

            // LogExceptionMessage should log the jws since CompleteSecurityArtifact is true.
            IdentityModelEventSource.LogCompleteSecurityArtifact = true;
            LogHelper.LogExceptionMessage(new SecurityTokenException(LogHelper.FormatInvariant(TestMessageOneParam,jws)));
            Assert.Contains(jws.EncodedToken, listener.TraceBuffer);
        }

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
