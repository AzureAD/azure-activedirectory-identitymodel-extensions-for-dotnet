// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.IdentityModel.TestUtils;
using Microsoft.IdentityModel.Tokens.Experimental;
using Microsoft.IdentityModel.Tokens.Saml2;
using Moq;
using Xunit;

namespace Microsoft.IdentityModel.Tokens.TokenValidation.Tests
{
#nullable enable
    public class Saml2Validation
    {
        #region Algorithm
        [Theory, MemberData(nameof(InvalidAlgorithmTestCases), DisableDiscoveryEnumeration = true)]
        public async Task InvalidAlgorithm(ValidateTokenTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.InvalidAlgorithm", theoryData);

            await ValidationUtils.RunInvalidTest(theoryData, context);

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<ValidateTokenTheoryData> InvalidAlgorithmTestCases()
        {
            return TestCaseProvider.GenerateInvalidAlgorithmTestCases(new Saml2SecurityTestingTokenHandler());
        }

        [Theory, MemberData(nameof(ValidAlgorithmTestCases), DisableDiscoveryEnumeration = true)]
        public async Task ValidAlgorithm(ValidateTokenTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.ValidAlgorithm", theoryData);

            await ValidationUtils.RunValidTest(theoryData, context);

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<ValidateTokenTheoryData> ValidAlgorithmTestCases()
        {
            return TestCaseProvider.GenerateValidAlgorithmTestCases(new Saml2SecurityTestingTokenHandler());
        }
        #endregion

        #region Audience
        [Theory, MemberData(nameof(InvalidAudienceTestCases), DisableDiscoveryEnumeration = true)]
        public async Task InvalidAudience(ValidateTokenTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.InvalidAudience", theoryData);

            await ValidationUtils.RunInvalidTest(theoryData, context);

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<ValidateTokenTheoryData> InvalidAudienceTestCases()
        {
            return TestCaseProvider.GenerateInvalidAudienceTestCases(new Saml2SecurityTestingTokenHandler());
        }

        [Theory, MemberData(nameof(ValidAudienceTestCases), DisableDiscoveryEnumeration = true)]
        public async Task ValidAudience(ValidateTokenTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.ValidAudience", theoryData);

            await ValidationUtils.RunValidTest(theoryData, context);

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<ValidateTokenTheoryData> ValidAudienceTestCases()
        {
            return TestCaseProvider.GenerateValidAudienceTestCases(new Saml2SecurityTestingTokenHandler());
        }

        [Theory]
        [InlineData(true, false, false)]
        [InlineData(false, true, false)]
        [InlineData(true, true, false)]
        [InlineData(false, false, false)]
        [InlineData(true, false, true)]
        [InlineData(false, true, true)]
        [InlineData(true, true, true)]
        [InlineData(false, false, true)]
        public async Task AudienceRestrictions(bool firstMatches, bool secondMatches, bool reverseOrder)
        {
            // Arrange
            const string firstAudience = "https://example.com/first";
            const string secondAudience = "https://example.com/second";
            List<string> firstAudiences =
                ["https://example.com/first-alternative", firstMatches ? firstAudience : "https://example.com/first-other"];
            List<string> secondAudiences =
                ["https://example.com/second-alternative", secondMatches ? secondAudience : "https://example.com/second-other"];

            if (reverseOrder)
                (firstAudiences, secondAudiences) = (secondAudiences, firstAudiences);

            var handler = new Saml2SecurityTokenHandler();
            var token = (Saml2SecurityToken)handler.CreateToken(new SecurityTokenDescriptor
            {
                Audience = Default.Audience,
                Issuer = Default.Issuer,
                SigningCredentials = Default.AsymmetricSigningCredentials,
                Subject = Default.ClaimsIdentityLongNames
            });
            token.Assertion.Conditions.AudienceRestrictions.Clear();
            token.Assertion.Conditions.AudienceRestrictions.Add(new Saml2AudienceRestriction(firstAudiences));
            token.Assertion.Conditions.AudienceRestrictions.Add(new Saml2AudienceRestriction(secondAudiences));
            string serializedToken = handler.WriteToken(token);

            var validationParameters = ValidationUtils.CreateValidationParameters(audiences: [firstAudience, secondAudience]);
            List<List<string>> validatedRestrictions = [];
            var audienceValidator = new Mock<IAudienceValidator>();
            audienceValidator.Setup(validator => validator.ValidateAudience(
                It.IsAny<IList<string>>(), It.IsAny<SecurityToken>(), validationParameters, It.IsAny<CallContext>()))
                .Returns((IList<string> audiences, SecurityToken? securityToken, ValidationParameters parameters, CallContext callContext) =>
                {
                    validatedRestrictions.Add([.. audiences]);
                    return Validators.ValidateAudience(audiences, securityToken, parameters, callContext);
                });
            validationParameters.AudienceValidator = audienceValidator.Object;

            // Act
            var result = await ((IResultBasedValidation)handler).ValidateTokenAsync(
                serializedToken, validationParameters, new CallContext());
            var matureResult = await handler.ValidateTokenAsync(
                serializedToken, ValidationUtils.CreateTokenValidationParameters(audiences: [firstAudience, secondAudience]));

            // Assert
            Assert.Equal(firstMatches && secondMatches, result.Succeeded);
            Assert.Equal(firstMatches && secondMatches, matureResult.IsValid);
            if (!result.Succeeded)
                Assert.IsType<AudienceValidationError>(result.Error);

            int expectedCalls = (reverseOrder ? secondMatches : firstMatches) ? 2 : 1;
            Assert.Equal(expectedCalls, validatedRestrictions.Count);
            Assert.Equal(firstAudiences, validatedRestrictions[0]);
            if (expectedCalls == 2)
                Assert.Equal(secondAudiences, validatedRestrictions[1]);
        }

        [Fact]
        public async Task NoAudienceRestrictionsUsesCustomValidator()
        {
            // Arrange
            var handler = new Saml2SecurityTokenHandler();
            var token = (Saml2SecurityToken)handler.CreateToken(new SecurityTokenDescriptor
            {
                Issuer = Default.Issuer,
                SigningCredentials = Default.AsymmetricSigningCredentials,
                Subject = Default.ClaimsIdentityLongNames
            });
            string serializedToken = handler.WriteToken(token);
            var validationParameters = ValidationUtils.CreateValidationParameters();
            var audienceValidator = new Mock<IAudienceValidator>();
            audienceValidator.Setup(validator => validator.ValidateAudience(
                It.Is<IList<string>>(audiences => audiences.Count == 0),
                It.IsAny<SecurityToken>(), validationParameters, It.IsAny<CallContext>()))
                .Returns(new ValidationResult<string, ValidationError>(Default.Audience));
            validationParameters.AudienceValidator = audienceValidator.Object;

            // Act
            var result = await ((IResultBasedValidation)handler).ValidateTokenAsync(
                serializedToken, validationParameters, new CallContext());

            // Assert
            Assert.True(result.Succeeded);
            audienceValidator.Verify(validator => validator.ValidateAudience(
                It.Is<IList<string>>(audiences => audiences.Count == 0),
                It.IsAny<SecurityToken>(), validationParameters, It.IsAny<CallContext>()), Times.Once);
        }
        #endregion

        #region Issuer
        [Theory, MemberData(nameof(InvalidIssuerTestCases), DisableDiscoveryEnumeration = true)]
        public async Task InvalidIssuer(ValidateTokenTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.InvalidIssuer", theoryData);
            await ValidationUtils.RunInvalidTest(theoryData, context);
            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<ValidateTokenTheoryData> InvalidIssuerTestCases()
        {
            return TestCaseProvider.GenerateInvalidIssuerTestCases(new Saml2SecurityTestingTokenHandler());
        }

        [Theory, MemberData(nameof(ValidIssuerTestCases), DisableDiscoveryEnumeration = true)]
        public async Task ValidIssuer(ValidateTokenTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.ValidIssuer", theoryData);
            await ValidationUtils.RunValidTest(theoryData, context);
            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<ValidateTokenTheoryData> ValidIssuerTestCases()
        {
            return TestCaseProvider.GenerateValidIssuerTestCases(new Saml2SecurityTestingTokenHandler());
        }
        #endregion

        #region IssuerSigningKey
        [Theory, MemberData(nameof(InvalidIssuerSigningKeyTestCases), DisableDiscoveryEnumeration = true)]
        public async Task InvalidIssuerSigningKey(ValidateTokenTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.InvalidIssuerSigningKey", theoryData);
            await ValidationUtils.RunInvalidTest(theoryData, context);
            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<ValidateTokenTheoryData> InvalidIssuerSigningKeyTestCases()
        {
            ITestingTokenHandler tokenHandler = new Saml2SecurityTestingTokenHandler();
            tokenHandler.SetDefaultTimesOnTokenCreation = false;
            return TestCaseProvider.GenerateInvalidIssuerSigningKeyTestCases(tokenHandler);
        }

        [Theory, MemberData(nameof(ValidIssuerSigningKeyTestCases), DisableDiscoveryEnumeration = true)]
        public async Task ValidIssuerSigningKey(ValidateTokenTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.ValidIssuerSigningKey", theoryData);
            await ValidationUtils.RunValidTest(theoryData, context);
            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<ValidateTokenTheoryData> ValidIssuerSigningKeyTestCases()
        {
            return TestCaseProvider.GenerateValidIssuerSigningKeyTestCases(new Saml2SecurityTestingTokenHandler());
        }
        #endregion

        #region Lifetime
        [Theory, MemberData(nameof(InvalidLifetimeTestCases), DisableDiscoveryEnumeration = true)]
        public async Task InvalidLifetime(ValidateTokenTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.InvalidLifetime", theoryData);

            await ValidationUtils.RunInvalidTest(theoryData, context);

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<ValidateTokenTheoryData> InvalidLifetimeTestCases()
        {
            Saml2SecurityTestingTokenHandler tokenHandler = new Saml2SecurityTestingTokenHandler();
            tokenHandler.SetDefaultTimesOnTokenCreation = false;
            return TestCaseProvider.GenerateInvalidLifetimeTestCases(tokenHandler);
        }

        [Theory, MemberData(nameof(ValidLifetimeTestCases), DisableDiscoveryEnumeration = true)]
        public async Task ValidLifetime(ValidateTokenTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.ValidLifetime", theoryData);

            await ValidationUtils.RunValidTest(theoryData, context);

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<ValidateTokenTheoryData> ValidLifetimeTestCases()
        {
            return TestCaseProvider.GenerateValidLifetimeTestCases(new Saml2SecurityTestingTokenHandler());
        }
        #endregion

        #region Signature
        [Theory, MemberData(nameof(InvalidSignatureTestCases), DisableDiscoveryEnumeration = true)]
        public async Task InvalidSignature(ValidateTokenTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.InvalidSignature", theoryData);
            theoryData.RelaxTVPException = true;
            await ValidationUtils.RunInvalidTest(theoryData, context);
            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<ValidateTokenTheoryData> InvalidSignatureTestCases()
        {
            ITestingTokenHandler tokenHandler = new Saml2SecurityTestingTokenHandler();
            tokenHandler.SetDefaultTimesOnTokenCreation = false;
            return TestCaseProvider.GenerateInvalidSignatureTestCases(tokenHandler);
        }

        [Theory, MemberData(nameof(ValidSignatureTestCases), DisableDiscoveryEnumeration = true)]
        public async Task ValidSignature(ValidateTokenTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.ValidSignature", theoryData);
            await ValidationUtils.RunValidTest(theoryData, context);
            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<ValidateTokenTheoryData> ValidSignatureTestCases()
        {
            return TestCaseProvider.GenerateValidSignatureTestCases(new Saml2SecurityTestingTokenHandler());
        }
        #endregion

        #region TokenReplay
        [Theory, MemberData(nameof(InvalidTokenReplayTestCases), DisableDiscoveryEnumeration = true)]
        public async Task InvalidTokenReplay(ValidateTokenTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.InvalidTokenReplay", theoryData);

            await ValidationUtils.RunInvalidTest(theoryData, context);

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<ValidateTokenTheoryData> InvalidTokenReplayTestCases()
        {
            Saml2SecurityTestingTokenHandler tokenHandler = new Saml2SecurityTestingTokenHandler();
            tokenHandler.SetDefaultTimesOnTokenCreation = false;
            return TestCaseProvider.GenerateInvalidTokenReplayTestCases(tokenHandler);
        }

        [Theory, MemberData(nameof(ValidTokenReplayTestCases), DisableDiscoveryEnumeration = true)]
        public async Task ValidTokenReplay(ValidateTokenTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.ValidTokenReplay", theoryData);

            await ValidationUtils.RunValidTest(theoryData, context);

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<ValidateTokenTheoryData> ValidTokenReplayTestCases()
        {
            return TestCaseProvider.GenerateValidTokenReplayTestCases(new Saml2SecurityTestingTokenHandler());
        }
        #endregion
    }
#nullable restore
}
