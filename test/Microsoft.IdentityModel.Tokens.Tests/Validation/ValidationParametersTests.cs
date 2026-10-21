// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Net;
using Xunit;
using Microsoft.IdentityModel.TestUtils;
using Microsoft.IdentityModel.Tokens.Experimental;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace Microsoft.IdentityModel.Tokens.Validation.Tests
{
    public class ValidationParametersTests
    {
        [Fact]
        public void CopyConstructor_CopiesAllValues()
        {
            // Arrange
            var documentRetriever = new HttpDocumentRetriever(HttpResponseMessageUtils.SetupHttpClientThatReturns("OpenIdConnectMetadata.json", HttpStatusCode.NotFound));
            var validationParameters = new CopyConstructibleValidationParameters
            {
                ActorValidationParameters = new ValidationParameters(),
                AlgorithmValidator = SkipValidationValidators.SkipAlgorithmValidation,
                AudienceValidator = SkipValidationValidators.SkipAudienceValidation,
                AuthenticationType = "authentication-type",
                ClockSkew = TimeSpan.FromMinutes(1),
                ConfigurationManager = new ConfigurationManager<OpenIdConnectConfiguration>("OpenIdConnectMetadata.json", new OpenIdConnectConfigurationRetriever(), documentRetriever),
                CryptoProviderFactory = new CryptoProviderFactory(),
                DebugId = "debug-id",
                IgnoreTrailingSlashWhenValidatingAudience = false,
                IgnoreCaseWhenValidatingAudience = true,
                IncludeTokenOnFailedValidation = true,
                SignatureKeyValidator = SkipValidationValidators.SkipIssuerSigningKeyValidation,
                SignatureKeyResolver = new TestSignatureKeyResolver(),
                IssuerValidatorAsync = SkipValidationValidators.SkipIssuerValidation,
                LifetimeValidator = SkipValidationValidators.SkipLifetimeValidation,
                LogTokenId = false,
                NameClaimType = "name-claim-type",
                NameClaimTypeRetriever = (token, issuer) => "retrieved-name-claim-type",
                RefreshBeforeValidation = true,
                RoleClaimType = "role-claim-type",
                RoleClaimTypeRetriever = (token, issuer) => "retrieved-role-claim-type",
                SaveSigninToken = true,
                SignatureValidator = SkipValidationValidators.SkipSignatureValidation,
                TimeProvider = new MockTimeProvider(),
                DecryptionKeyResolver = new TestDecryptionKeyResolver(),
                TokenReplayCache = new TokenReplayCache(),
                TokenReplayValidator = SkipValidationValidators.SkipTokenReplayValidation,
                TryAllDecryptionKeys = false,
                TryAllSigningKeys = true,
                TokenTypeValidator = SkipValidationValidators.SkipTokenTypeValidation,
                ValidateWithLKG = true,
                ValidateActor = true
            };

            validationParameters.InstancePropertyBag["instance"] = new object();
            validationParameters.PropertyBag["property"] = new object();
            validationParameters.SigningKeys.Add(new SymmetricSecurityKey(new byte[32]));
            validationParameters.DecryptionKeys.Add(new SymmetricSecurityKey(new byte[32]));
            validationParameters.ValidAlgorithms.Add("algorithm");
            validationParameters.ValidAudiences.Add("audience");
            validationParameters.ValidIssuers.Add("issuer");
            validationParameters.ValidTypes.Add("type");

            // Act
            var copy = new CopyConstructibleValidationParameters(validationParameters);

            // Assert
            var compareContext = new CompareContext();
            compareContext.PropertiesToIgnoreWhenComparing.Add(
                typeof(CopyConstructibleValidationParameters),
                new List<string> { nameof(ValidationParameters.InstancePropertyBag) });

            IdentityComparer.CompareAllPublicProperties(validationParameters, copy, compareContext);
            TestUtilities.AssertFailIfErrors(compareContext);

            Assert.Same(validationParameters.TimeProvider, copy.TimeProvider);
            Assert.Same(validationParameters.DecryptionKeyResolver, copy.DecryptionKeyResolver);
            Assert.NotSame(validationParameters.InstancePropertyBag, copy.InstancePropertyBag);
            Assert.Empty(copy.InstancePropertyBag);
        }

        [Fact]
        public void CopyConstructor_CreatesIndependentCollections()
        {
            // Arrange
            var original = new ValidationParameters();
            var originalKey = new SymmetricSecurityKey(new byte[32]);
            original.SigningKeys.Add(originalKey);
            original.DecryptionKeys.Add(originalKey);
            original.ValidIssuers.Add("issuer");
            original.ValidAudiences.Add("audience");
            original.ValidAlgorithms.Add("algorithm");
            original.ValidTypes.Add("type");

            // Act
            var copy = new CopyConstructibleValidationParameters(original);
            copy.SigningKeys.Add(new SymmetricSecurityKey(new byte[32]));
            copy.DecryptionKeys.Add(new SymmetricSecurityKey(new byte[32]));
            copy.ValidIssuers.Add("copy-issuer");
            copy.ValidAudiences.Add("copy-audience");
            copy.ValidAlgorithms.Add("copy-algorithm");
            copy.ValidTypes.Add("copy-type");

            // Assert
            Assert.Single(original.SigningKeys);
            Assert.Single(original.DecryptionKeys);
            Assert.Single(original.ValidIssuers);
            Assert.Single(original.ValidAudiences);
            Assert.Single(original.ValidAlgorithms);
            Assert.Single(original.ValidTypes);
        }

        [Fact]
        public void SetValidators_NullValue_ThrowsArgumentNullException()
        {
            var validationParameters = new ValidationParameters();
            Assert.Throws<ArgumentNullException>(() => validationParameters.IssuerValidatorAsync = null);
            Assert.Throws<ArgumentNullException>(() => validationParameters.TokenReplayValidator = null);
            Assert.Throws<ArgumentNullException>(() => validationParameters.LifetimeValidator = null);
            Assert.Throws<ArgumentNullException>(() => validationParameters.TokenTypeValidator = null);
            Assert.Throws<ArgumentNullException>(() => validationParameters.AudienceValidator = null);
            Assert.Throws<ArgumentNullException>(() => validationParameters.SignatureKeyValidator = null);
        }

        [Fact]
        public void ValidIssuers_GetReturnsEmptyList()
        {
            var validationParameters = new ValidationParameters();

            Assert.Empty(validationParameters.ValidIssuers);
        }

        [Fact]
        public void ValidAudiences_Get_ReturnsEmptyList()
        {
            var validationParameters = new ValidationParameters();

            Assert.Empty(validationParameters.ValidAudiences);
            Assert.True(validationParameters.ValidAudiences is IList<string>);
        }

        [Fact]
        public void ValidTypes_Get_ReturnsEmptyList()
        {
            var validationParameters = new ValidationParameters();

            Assert.Empty(validationParameters.ValidTypes);
            Assert.True(validationParameters.ValidTypes is IList<string>);
        }

        [Fact]
        public void Valid_Set_TimeProvider()
        {
            TimeProvider timeProvider = new MockTimeProvider();
            var validationParameters = new ValidationParameters()
            {
                TimeProvider = timeProvider
            };

            Assert.Equal(validationParameters.TimeProvider, timeProvider);
        }

        [Fact]
        public void Valid_NotNull_TimeProvider()
        {
            var validationParameters = new ValidationParameters();

            Assert.NotNull(validationParameters.TimeProvider);
        }

        private sealed class CopyConstructibleValidationParameters : ValidationParameters
        {
            public CopyConstructibleValidationParameters()
            {
            }

            public CopyConstructibleValidationParameters(ValidationParameters other)
                : base(other)
            {
            }
        }

        private sealed class TestSignatureKeyResolver : ISignatureKeyResolver
        {
            public SecurityKey ResolveSignatureKey(
                string token,
                SecurityToken securityToken,
                string kid,
                ValidationParameters validationParameters,
                BaseConfiguration configuration,
                CallContext callContext)
            {
                return validationParameters.SigningKeys[0];
            }
        }

        private sealed class TestDecryptionKeyResolver : IDecryptionKeyResolver
        {
            public IList<SecurityKey> ResolveDecryptionKey(
                string token,
                SecurityToken securityToken,
                string kid,
                ValidationParameters validationParameters,
                CallContext callContext)
            {
                return validationParameters.DecryptionKeys;
            }
        }
    }
}
