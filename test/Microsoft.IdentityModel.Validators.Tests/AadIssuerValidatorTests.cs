// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.TestUtils;
using Xunit;

namespace Microsoft.IdentityModel.Validators.Tests
{
    public class AadIssuerValidatorTests
    {
        [Theory, MemberData(nameof(AadIssuerValidationTestCases), DisableDiscoveryEnumeration = true)]
        public static void IsValidIssuer_ValidatesIssuersCorrectly(AadIssuerValidatorTheoryData theoryData)
        {
            // Act
            var validationResult = AadIssuerValidator.IsValidIssuer(
                theoryData.TemplatedIssuer,
                theoryData.TenantIdClaim,
                theoryData.TokenIssuer);

            // Assert
            Assert.Equal(theoryData.ExpectedResult, validationResult);
        }

        [Fact]
        public void GetAadIssuerValidator_ThrowsOnNullOrEmptyAuthority()
        {
            Assert.Throws<ArgumentNullException>(() =>
                AadIssuerValidator.GetAadIssuerValidator(null, null, null));
            Assert.Throws<ArgumentNullException>(() =>
                AadIssuerValidator.GetAadIssuerValidator("", null, null));
        }

        [Fact]
        public void GetAadIssuerValidator_ReturnsInstance_WithAndWithoutProvider()
        {
            string authority = "https://login.microsoftonline.com/common";
            HttpClient httpClient = new HttpClient();

            // Without provider
            var validator1 = AadIssuerValidator.GetAadIssuerValidator(authority, httpClient, null);
            Assert.NotNull(validator1);

            // With provider
            Func<string, BaseConfigurationManager> provider = (auth) => new MockBaseConfigurationManager();
            var validator2 = AadIssuerValidator.GetAadIssuerValidator(authority, httpClient, provider);
            Assert.NotNull(validator2);

            // Should return the same instance for the same authority when provider is null
            var validator3 = AadIssuerValidator.GetAadIssuerValidator(authority, httpClient, null);
            Assert.Same(validator1, validator3);
        }

        [Theory]
        [InlineData(ValidatorConstants.AuthorityCommonTenantWithV2, ValidatorConstants.AadIssuer, ValidatorConstants.AadIssuerV2CommonAuthority, true)]
        [InlineData(ValidatorConstants.AuthorityCommonTenantWithV2, ValidatorConstants.V1Issuer, ValidatorConstants.AadIssuerV1CommonAuthority, true)]
        [InlineData(ValidatorConstants.AuthorityV1, ValidatorConstants.AadIssuer, ValidatorConstants.AadIssuerV2CommonAuthority, true)]
        [InlineData(ValidatorConstants.AuthorityCommonTenantWithV2, ValidatorConstants.AadIssuerPPE, ValidatorConstants.AadIssuerV2CommonAuthority, false)]
        public async Task ValidateTokenAsync_WithDelayedIssuerMetadata_DoesNotBlock(
            string authority, string issuer, string metadataIssuer, bool expectedIsValid)
        {
            // Arrange
            var configuration = new TaskCompletionSource<BaseConfiguration>(TaskCreationOptions.RunContinuationsAsynchronously);
            var configurationManager = new DelayedConfigurationManager(configuration.Task);
            var issuerValidator = AadIssuerValidator.GetAadIssuerValidator(authority, null, _ => configurationManager);
            var handler = new JsonWebTokenHandler();
            string token = handler.CreateToken(new SecurityTokenDescriptor
            {
                Issuer = issuer,
                Audience = Default.Audience,
                Claims = new Dictionary<string, object> { { ValidatorConstants.ClaimNameTid, ValidatorConstants.TenantIdAsGuid } },
                SigningCredentials = KeyingMaterial.DefaultSymmetricSigningCreds_256_Sha2
            });
            var validationParameters = new TokenValidationParameters
            {
                ValidAudience = Default.Audience,
                IssuerSigningKey = KeyingMaterial.DefaultSymmetricSecurityKey_256,
                IssuerValidatorAsync = issuerValidator.ValidateAsync,
                IssuerValidator = (_, _, _) => throw new InvalidOperationException("The synchronous issuer validator must not run."),
                IssuerValidatorUsingConfiguration = (_, _, _, _) => throw new InvalidOperationException("The synchronous issuer validator must not run.")
            };

            // Act
            // A worker and a finally-released gate keep a blocking regression from hanging the test.
            Task<Task<TokenValidationResult>[]> invocation = Task.Run(() =>
            {
                var validations = new Task<TokenValidationResult>[8];
                for (int i = 0; i < validations.Length; i++)
                    validations[i] = handler.ValidateTokenAsync(token, validationParameters.Clone());

                return validations;
            });

            try
            {
                Task completed = await Task.WhenAny(invocation, Task.Delay(TimeSpan.FromSeconds(10)));

                // Assert
                Assert.Same(invocation, completed);
                foreach (Task<TokenValidationResult> validation in await invocation)
                    Assert.False(validation.IsCompleted);
            }
            finally
            {
                configuration.TrySetResult(new OpenIdConnectConfiguration { Issuer = metadataIssuer });
                await Task.WhenAll(await invocation);
            }

            foreach (TokenValidationResult result in await Task.WhenAll(await invocation))
            {
                Assert.Equal(expectedIsValid, result.IsValid);
                if (!expectedIsValid)
                    Assert.IsType<SecurityTokenInvalidIssuerException>(result.Exception);
            }
        }

        [Fact]
        public async Task ValidateAsync_MetadataRetrievalFailure_PreservesException()
        {
            // Arrange
            var metadataException = new HttpRequestException("Metadata is unavailable.");
            var configurationManager = new DelayedConfigurationManager(Task.FromException<BaseConfiguration>(metadataException));
            var issuerValidator = AadIssuerValidator.GetAadIssuerValidator(
                ValidatorConstants.AuthorityCommonTenantWithV2, null, _ => configurationManager);
            var token = new JsonWebToken("{}", $"{{\"iss\":\"{ValidatorConstants.AadIssuer}\",\"tid\":\"{ValidatorConstants.TenantIdAsGuid}\"}}");

            // Act
            SecurityTokenInvalidIssuerException exception = await Assert.ThrowsAsync<SecurityTokenInvalidIssuerException>(
                async () => await issuerValidator.ValidateAsync(token.Issuer, token, new TokenValidationParameters()));

            // Assert
            Assert.Same(metadataException, exception.InnerException);
        }

        public static TheoryData<AadIssuerValidatorTheoryData> AadIssuerValidationTestCases()
        {
            var theoryData = new TheoryData<AadIssuerValidatorTheoryData>
            {
                // Success cases
                new AadIssuerValidatorTheoryData("V1_TemplateWithoutTrailingSlash_Matches_V1_IssuerWithoutTrailingSlash_Success")
                {
                    TemplatedIssuer = ValidatorConstants.AadIssuerV1CommonAuthorityWithoutTrailingSlash,
                    TokenIssuer = ValidatorConstants.V1IssuerWithoutTrailingSlash,
                    TenantIdClaim = ValidatorConstants.TenantIdAsGuid,
                    ExpectedResult = true,
                },
                new AadIssuerValidatorTheoryData("V1_Template_Matches_V1_Issuer_Success")
                {
                    TemplatedIssuer = ValidatorConstants.AadIssuerV1CommonAuthority,
                    TokenIssuer = ValidatorConstants.V1Issuer,
                    TenantIdClaim = ValidatorConstants.TenantIdAsGuid,
                    ExpectedResult = true,
                },
                new AadIssuerValidatorTheoryData("V2_Template_Matches_V2_Issuer_Success")
                {
                    TemplatedIssuer = ValidatorConstants.AadIssuerV2CommonAuthority,
                    TokenIssuer = ValidatorConstants.AadIssuer,
                    TenantIdClaim = ValidatorConstants.TenantIdAsGuid,
                    ExpectedResult = true,
                },
                new AadIssuerValidatorTheoryData("IssuerTemplate_WithTenantId_TokenIssuer_Match_Success")
                {
                    TemplatedIssuer = ValidatorConstants.AadIssuer,
                    TokenIssuer = ValidatorConstants.AadIssuer,
                    TenantIdClaim = ValidatorConstants.TenantIdAsGuid,
                    ExpectedResult = true,
                },

                // Failure cases
                new AadIssuerValidatorTheoryData("V1_Template_With_V2_Issuer_Failure")
                {
                    TemplatedIssuer = ValidatorConstants.AadIssuerV1CommonAuthority,
                    TokenIssuer = ValidatorConstants.AadIssuer,
                    TenantIdClaim = ValidatorConstants.TenantIdAsGuid,
                    ExpectedResult = false,
                },
                new AadIssuerValidatorTheoryData("V2_Template_With_V1_Issuer_Failure")
                {
                    TemplatedIssuer = ValidatorConstants.AadIssuerV2CommonAuthority,
                    TokenIssuer = ValidatorConstants.V1Issuer,
                    TenantIdClaim = ValidatorConstants.TenantIdAsGuid,
                    ExpectedResult = false,
                },
                new AadIssuerValidatorTheoryData("Null_TokenIssuer_Failure")
                {
                    TemplatedIssuer = ValidatorConstants.AadIssuerV1CommonAuthority,
                    TokenIssuer = "",
                    TenantIdClaim = ValidatorConstants.TenantIdAsGuid,
                    ExpectedResult = false,
                },
                new AadIssuerValidatorTheoryData("Null_TenantId_Failure")
                {
                    TemplatedIssuer = ValidatorConstants.AadIssuerV1CommonAuthority,
                    TokenIssuer = ValidatorConstants.AadIssuer,
                    TenantIdClaim = "",
                    ExpectedResult = false,
                },
                new AadIssuerValidatorTheoryData("PPE_Template_With_V1_Issuer_Failure")
                {
                    TemplatedIssuer = ValidatorConstants.AadInstancePPE + "/" + AadIssuerValidator.TenantIdTemplate,
                    TokenIssuer =  ValidatorConstants.AadInstance + "/" + ValidatorConstants.TenantIdAsGuid,
                    TenantIdClaim = ValidatorConstants.TenantIdAsGuid,
                    ExpectedResult = false,
                },
                new AadIssuerValidatorTheoryData("Malformed_V2_TokenIssuer_Failure")
                {
                    TemplatedIssuer = ValidatorConstants.AadIssuerV2CommonAuthority,
                    TokenIssuer = "https://login.microsoftonline.com/{tenantid}/v2.0",
                    TenantIdClaim = ValidatorConstants.TenantIdAsGuid,
                    ExpectedResult = false,
                },
                new AadIssuerValidatorTheoryData("IssuerTemplate_WithTenantId_TokenIssuer_NoMatch_Failure")
                {
                    TemplatedIssuer = ValidatorConstants.AadIssuerPPE,
                    TokenIssuer = ValidatorConstants.AadIssuer,
                    TenantIdClaim = ValidatorConstants.TenantIdAsGuid,
                    ExpectedResult = false,
                },
            };

            return theoryData;
        }

        private class DelayedConfigurationManager : BaseConfigurationManager
        {
            private readonly Task<BaseConfiguration> _configuration;

            public DelayedConfigurationManager(Task<BaseConfiguration> configuration)
            {
                _configuration = configuration;
            }

            public override Task<BaseConfiguration> GetBaseConfigurationAsync(CancellationToken cancellationToken)
            {
                return _configuration;
            }

            public override void RequestRefresh() { }
        }

        private class MockBaseConfigurationManager : BaseConfigurationManager
        {
            public override void RequestRefresh() { }
        }
    }

    public class AadIssuerValidatorTheoryData : TheoryDataBase
    {
        public AadIssuerValidatorTheoryData() { }

        public AadIssuerValidatorTheoryData(string testId) : base(testId) { }

        public string TemplatedIssuer { get; set; }

        public string TokenIssuer { get; set; }

        public string TenantIdClaim { get; set; }

        public bool ExpectedResult { get; set; }
    }
}
