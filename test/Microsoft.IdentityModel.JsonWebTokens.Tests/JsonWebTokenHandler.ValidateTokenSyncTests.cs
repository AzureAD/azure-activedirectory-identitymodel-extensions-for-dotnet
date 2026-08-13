// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.TestExtensions;
using Microsoft.IdentityModel.TestUtils;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace Microsoft.IdentityModel.JsonWebTokens.Tests
{
    public class JsonWebTokenHandlerValidateTokenSyncTests
    {
        private readonly TestTokenCreator _testTokenCreator = new()
        {
            SigningCredentials = KeyingMaterial.JsonWebKeyRsa256SigningCredentials
        };

        private readonly JsonWebTokenHandler _jsonWebTokenHandler = new();

        [Fact]
        public void TestNotYetValidToken()
        {
            TokenValidationResult validationResult = ValidateToken(_testTokenCreator.CreateNotYetValidToken());

            Assert.False(validationResult.IsValid);
            Assert.Null(validationResult.SecurityToken);
            Assert.IsType<SecurityTokenNotYetValidException>(validationResult.Exception);
        }

        [Fact]
        public void TestTokenWithFutureIssuedAt()
        {
            TokenValidationResult validationResult = ValidateToken(_testTokenCreator.CreateTokenWithFutureIssuedAt());

            Assert.True(validationResult.IsValid);
            Assert.NotNull(validationResult.SecurityToken);
            Assert.Null(validationResult.Exception);
        }

        [Fact]
        public void TestTokenWithMissingIssuedAt()
        {
            TokenValidationResult validationResult = ValidateToken(_testTokenCreator.CreateTokenWithMissingIssuedAt());

            Assert.True(validationResult.IsValid);
            Assert.NotNull(validationResult.SecurityToken);
            Assert.Null(validationResult.Exception);
        }

        [Fact]
        public void TestTokenWithMissingNotBefore()
        {
            TokenValidationResult validationResult = ValidateToken(_testTokenCreator.CreateTokenWithMissingNotBefore());

            Assert.True(validationResult.IsValid);
            Assert.NotNull(validationResult.SecurityToken);
            Assert.Null(validationResult.Exception);
        }

        [Fact]
        public void TestTokenSucceeds()
        {
            TokenValidationResult validationResult = ValidateToken(_testTokenCreator.CreateDefaultValidToken());

            Assert.True(validationResult.IsValid);
            Assert.NotNull(validationResult.SecurityToken);
            Assert.Null(validationResult.Exception);
        }

#if NET5_0_OR_GREATER
        [Fact]
        public void ValidateToken_UsesSeparateSyncConfigurationManager()
        {
            AppContextSwitches.ResetAllSwitches();
            AppContext.SetSwitch(AppContextSwitches.PreserveLegacySyncBehaviorSwitch, false);

            try
            {
                var syncConfiguration = new OpenIdConnectConfiguration
                {
                    Issuer = "http://Default.Issuer.com",
                };
                syncConfiguration.SigningKeys.Add(KeyingMaterial.JsonWebKeyRsa256SigningCredentials.Key);

                var asyncConfiguration = new OpenIdConnectConfiguration
                {
                    Issuer = "different-issuer",
                };

                TokenValidationParameters validationParameters = new()
                {
                    ConfigurationManager = new StaticConfigurationManager<OpenIdConnectConfiguration>(asyncConfiguration),
                    ConfigurationManagerSync = new TestConfigurationManagerSync(syncConfiguration),
                    ValidAudiences = ["http://Default.Audience.com"],
                };

#pragma warning disable CS0618 // Legacy synchronous overload is intentionally exercised here.
                TokenValidationResult validationResult = _jsonWebTokenHandler.ValidateToken(
                    _testTokenCreator.CreateDefaultValidToken(),
                    validationParameters);
#pragma warning restore CS0618

                Assert.True(validationResult.IsValid);
                Assert.Same(
                    validationParameters.ConfigurationManagerSync,
                    validationParameters.Clone().ConfigurationManagerSync);
            }
            finally
            {
                AppContextSwitches.ResetAllSwitches();
            }
        }
#endif

        [Theory]
#if NET5_0_OR_GREATER
        [InlineData(false, false, true)]
#else
        [InlineData(false, true, false)]
#endif
        [InlineData(true, true, false)]
        public void PreserveLegacySyncBehavior_SelectsValidationPath(
            bool preserveLegacySyncBehavior,
            bool expectedAsyncValidator,
            bool expectedSyncValidator)
        {
            AppContextSwitches.ResetAllSwitches();
            AppContext.SetSwitch(AppContextSwitches.PreserveLegacySyncBehaviorSwitch, preserveLegacySyncBehavior);

            bool asyncValidatorCalled = false;
            bool syncValidatorCalled = false;

            try
            {
                TokenValidationParameters validationParameters = CreateTokenValidationParameters();
                validationParameters.IssuerValidatorAsync = (issuer, token, parameters) =>
                {
                    asyncValidatorCalled = true;
                    return new ValueTask<string>(issuer);
                };
                validationParameters.IssuerValidatorSync = (issuer, token, parameters) =>
                {
                    syncValidatorCalled = true;
                    return issuer;
                };

#pragma warning disable CS0618 // Legacy synchronous overload is intentionally exercised here.
                TokenValidationResult validationResult = _jsonWebTokenHandler.ValidateToken(
                    _testTokenCreator.CreateDefaultValidToken(),
                    validationParameters);
#pragma warning restore CS0618

                Assert.True(validationResult.IsValid);
                Assert.Equal(expectedAsyncValidator, asyncValidatorCalled);
                Assert.Equal(expectedSyncValidator, syncValidatorCalled);
            }
            finally
            {
                AppContextSwitches.ResetAllSwitches();
            }
        }

        private TokenValidationResult ValidateToken(string token)
        {
#pragma warning disable CS0618 // Legacy synchronous overload is intentionally exercised here.
            return _jsonWebTokenHandler.ValidateToken(token, CreateTokenValidationParameters());
#pragma warning restore CS0618
        }

        private static TokenValidationParameters CreateTokenValidationParameters() =>
            new()
            {
                ValidAudiences = ["http://Default.Audience.com"],
                ValidIssuers = ["http://Default.Issuer.com"],
                IssuerSigningKeys = [KeyingMaterial.JsonWebKeyRsa256SigningCredentials.Key],
            };

        private sealed class TestConfigurationManagerSync : BaseConfigurationManagerSync
        {
            private readonly BaseConfiguration _configuration;

            public TestConfigurationManagerSync(BaseConfiguration configuration)
            {
                _configuration = configuration;
            }

            internal override BaseConfiguration GetBaseConfigurationSync(CancellationToken cancellationToken)
            {
                return _configuration;
            }

            public override void RequestRefresh()
            {
            }
        }
    }
}
