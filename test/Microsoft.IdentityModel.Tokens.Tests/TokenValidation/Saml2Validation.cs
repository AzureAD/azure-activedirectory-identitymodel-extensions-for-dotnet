// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.IdentityModel.TestUtils;
using Microsoft.IdentityModel.Tokens.Experimental;
using Microsoft.IdentityModel.Tokens.Saml2;
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
        public async Task AudienceRestrictions(bool matchesFirst, bool matchesSecond, bool reverseRestrictions)
        {
            // Arrange
            var handler = new Saml2SecurityTestingTokenHandler();
            Saml2SecurityToken token = CreateAudienceRestrictionsToken(handler, reverseRestrictions);
            ValidationParameters parameters = ValidationUtils.CreateValidationParameters(audiences: ["urn:audience:unmatched"]);
            if (matchesFirst)
                parameters.ValidAudiences.Add("urn:audience:first");
            if (matchesSecond)
                parameters.ValidAudiences.Add("urn:audience:second");

            parameters.SignatureValidator = SkipValidationDelegates.SkipSignatureValidation;
            parameters.SignatureKeyValidator = SkipValidationDelegates.SkipIssuerSigningKeyValidation;

            // Act
            var result = await handler.ValidateTokenAsync(token, parameters, new CallContext(), default);

            // Assert
            Assert.Equal(matchesFirst && matchesSecond, result.Succeeded);
            if (result.Succeeded)
                Assert.Equal(reverseRestrictions ? "urn:audience:second" : "urn:audience:first", result.Result!.ValidatedAudience);
            else
            {
                Assert.IsType<AudienceValidationError>(result.Error);
                Assert.Equal(AudienceValidationFailure.AudienceDidNotMatch, result.Error!.FailureType);
            }
        }

        [Theory]
        [InlineData(0)]
        [InlineData(1)]
        [InlineData(2)]
        public async Task AudienceRestrictions_CustomValidator(int failingRestriction)
        {
            // Arrange
            var handler = new Saml2SecurityTestingTokenHandler();
            Saml2SecurityToken token = CreateAudienceRestrictionsToken(handler);
            ValidationParameters parameters = ValidationUtils.CreateValidationParameters();
            parameters.SignatureValidator = SkipValidationDelegates.SkipSignatureValidation;
            parameters.SignatureKeyValidator = SkipValidationDelegates.SkipIssuerSigningKeyValidation;
            var expectedError = new AudienceValidationError(
                new MessageDetail("Audience restriction validation failed."),
                AudienceValidationFailure.AudienceDidNotMatch,
                ValidationError.GetCurrentStackFrame(),
                null,
                parameters.ValidAudiences);
            List<IList<string>> validatedRestrictions = [];
            parameters.AudienceValidator = (audiences, _, _, _) =>
            {
                validatedRestrictions.Add(audiences);
                if (validatedRestrictions.Count == failingRestriction)
                    return expectedError;

                return audiences[0];
            };

            // Act
            var result = await handler.ValidateTokenAsync(token, parameters, new CallContext(), default);

            // Assert
            Assert.Equal(failingRestriction == 0, result.Succeeded);
            Assert.Equal(failingRestriction == 1 ? 1 : 2, validatedRestrictions.Count);
            Assert.Equal(new[] { "urn:audience:first:alternative", "urn:audience:first" }, validatedRestrictions[0]);
            if (validatedRestrictions.Count == 2)
                Assert.Equal(new[] { "urn:audience:second", "urn:audience:second:alternative" }, validatedRestrictions[1]);

            if (result.Succeeded)
                Assert.Equal("urn:audience:first:alternative", result.Result!.ValidatedAudience);
            else
                Assert.Same(expectedError, result.Error);
        }

        [Theory]
        [InlineData(false, false)]
        [InlineData(true, false)]
        [InlineData(true, true)]
        public async Task AudienceRestrictions_Empty(bool hasConditions, bool hasEmptyRestriction)
        {
            // Arrange
            var handler = new Saml2SecurityTestingTokenHandler();
            Saml2SecurityToken token = CreateAudienceRestrictionsToken(handler);
            token.Assertion.Conditions.AudienceRestrictions.Clear();
            if (hasEmptyRestriction)
                token.Assertion.Conditions.AudienceRestrictions.Add(new Saml2AudienceRestriction([]));
            if (!hasConditions)
                token.Assertion.Conditions = null;

            ValidationParameters parameters = ValidationUtils.CreateValidationParameters();
            parameters.LifetimeValidator = SkipValidationDelegates.SkipLifetimeValidation;
            parameters.SignatureValidator = SkipValidationDelegates.SkipSignatureValidation;
            parameters.SignatureKeyValidator = SkipValidationDelegates.SkipIssuerSigningKeyValidation;

            // Act
            var result = await handler.ValidateTokenAsync(token, parameters, new CallContext(), default);

            // Assert
            Assert.False(result.Succeeded);
            Assert.IsType<AudienceValidationError>(result.Error);
            Assert.Equal(AudienceValidationFailure.NoAudienceInToken, result.Error!.FailureType);

            int validatorCalls = 0;
            parameters.AudienceValidator = (audiences, _, _, _) =>
            {
                validatorCalls++;
                Assert.Empty(audiences);
                return "accepted";
            };
            result = await handler.ValidateTokenAsync(token, parameters, new CallContext(), default);

            Assert.True(result.Succeeded);
            Assert.Equal(1, validatorCalls);
            Assert.Equal("accepted", result.Result!.ValidatedAudience);
        }

        private static Saml2SecurityToken CreateAudienceRestrictionsToken(
            Saml2SecurityTestingTokenHandler handler,
            bool reverseRestrictions = false)
        {
            SecurityTokenDescriptor descriptor = Default.SecurityTokenDescriptor(Default.AsymmetricSigningCredentials);
            descriptor.Subject = Default.ClaimsIdentityLongNames;
            var token = (Saml2SecurityToken)handler.CreateToken(descriptor);
            var firstRestriction = new Saml2AudienceRestriction(
                ["urn:audience:first:alternative", "urn:audience:first"]);
            var secondRestriction = new Saml2AudienceRestriction(
                ["urn:audience:second", "urn:audience:second:alternative"]);
            token.Assertion.Conditions.AudienceRestrictions.Clear();
            token.Assertion.Conditions.AudienceRestrictions.Add(reverseRestrictions ? secondRestriction : firstRestriction);
            token.Assertion.Conditions.AudienceRestrictions.Add(reverseRestrictions ? firstRestriction : secondRestriction);

            return token;
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
