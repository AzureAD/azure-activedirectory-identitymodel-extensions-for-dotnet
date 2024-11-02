// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System.Threading;
using System.Threading.Tasks;
using Microsoft.IdentityModel.TestUtils;
using Xunit;

namespace Microsoft.IdentityModel.Tokens.Saml.Tests
{
#nullable enable
    public partial class SamlSecurityTokenHandlerTests
    {
        [Theory, MemberData(nameof(ValidateTokenAsync_IssuerTestCases), DisableDiscoveryEnumeration = true)]
        public async Task ValidateTokenAsync_IssuerComparison(ValidateTokenAsyncIssuerTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.ValidateTokenAsync_IssuerComparison", theoryData);

            SamlSecurityTokenHandler samlTokenHandler = new SamlSecurityTokenHandler();

            var samlToken = CreateTokenWithIssuer(theoryData.TokenIssuer);

            var tokenValidationParameters = CreateTokenValidationParametersForIssuerValidationOnly(
                samlToken,
                theoryData.NullTokenValidationParameters,
                theoryData.ValidationParametersIssuer);

            // Validate token using TokenValidationParameters
            TokenValidationResult tokenValidationResult =
                await samlTokenHandler.ValidateTokenAsync(samlToken.Assertion.CanonicalString, tokenValidationParameters);

            // Validate token using ValidationParameters.
            ValidationResult<ValidatedToken> validationResult =
                await samlTokenHandler.ValidateTokenAsync(
                    samlToken,
                    theoryData.ValidationParameters!,
                    theoryData.CallContext,
                    CancellationToken.None);

            // Ensure validity of the results match the expected result.
            if (tokenValidationResult.IsValid != validationResult.IsValid)
            {
                context.AddDiff($"tokenValidationResult.IsValid != validationResult.IsSuccess");
                theoryData.ExpectedExceptionValidationParameters!.ProcessException(validationResult.UnwrapError().GetException(), context);
                theoryData.ExpectedException.ProcessException(tokenValidationResult.Exception, context);
            }
            else
            {
                if (tokenValidationResult.IsValid)
                {
                    // Verify validated tokens from both paths match.
                    ValidatedToken validatedToken = validationResult.UnwrapResult();
                    IdentityComparer.AreEqual(validatedToken.SecurityToken, tokenValidationResult.SecurityToken, context);
                }
                else
                {
                    // Verify the exception provided by both paths match.
                    var tokenValidationResultException = tokenValidationResult.Exception;
                    theoryData.ExpectedException.ProcessException(tokenValidationResult.Exception, context);
                    var validationResultException = validationResult.UnwrapError().GetException();
                    theoryData.ExpectedExceptionValidationParameters!.ProcessException(validationResult.UnwrapError().GetException(), context);
                }

                TestUtilities.AssertFailIfErrors(context);
            }
        }

        public static TheoryData<ValidateTokenAsyncIssuerTheoryData> ValidateTokenAsync_IssuerTestCases
        {
            get
            {
                var theoryData = new TheoryData<ValidateTokenAsyncIssuerTheoryData>();

                theoryData.Add(new ValidateTokenAsyncIssuerTheoryData("Valid_IssuerIsValidIssuer")
                {
                    TokenIssuer = Default.Issuer,
                    ValidationParametersIssuer = Default.Issuer,
                    ValidationParameters = CreateValidationParameters(validIssuer: Default.Issuer),
                });

                theoryData.Add(new ValidateTokenAsyncIssuerTheoryData("Invalid_IssuerIsNotValid")
                {
                    TokenIssuer = "InvalidIssuer",
                    ValidationParametersIssuer = Default.Issuer,
                    ValidationParameters = CreateValidationParameters(validIssuer: Default.Issuer),
                    ExpectedIsValid = false,
                    ExpectedException = new ExpectedException(typeof(SecurityTokenInvalidIssuerException), "IDX10205:"),
                    ExpectedExceptionValidationParameters = new ExpectedException(typeof(SecurityTokenInvalidIssuerException), "IDX10212:")
                });

                theoryData.Add(new ValidateTokenAsyncIssuerTheoryData("Invalid_IssuerIsWhitespace")
                {
                    //This test will cover the case where the issuer is null or empty as well since, we do not allow tokens to be created with null or empty issuer.
                    TokenIssuer = " ",
                    ValidationParametersIssuer = Default.Issuer,
                    ValidationParameters = CreateValidationParameters(validIssuer: Default.Issuer),
                    ExpectedIsValid = false,
                    ExpectedException = new ExpectedException(typeof(SecurityTokenInvalidIssuerException), "IDX10211:")
                });

                theoryData.Add(new ValidateTokenAsyncIssuerTheoryData("Invalid_NoValidIssuersProvided")
                {
                    TokenIssuer = Default.Issuer,
                    ValidationParametersIssuer = string.Empty,
                    ValidationParameters = CreateValidationParameters(),
                    ExpectedIsValid = false,
                    ExpectedException = new ExpectedException(typeof(SecurityTokenInvalidIssuerException), "IDX10204:"),
                    ExpectedExceptionValidationParameters = new ExpectedException(typeof(SecurityTokenInvalidIssuerException), "IDX10211:")
                });

                return theoryData;

                static ValidationParameters CreateValidationParameters(
                    string? validIssuer = null,
                    string? configurationIssuer = null)
                {
                    ValidationParameters validationParameters = new ValidationParameters();

                    // Skip all validations except issuer
                    validationParameters.AlgorithmValidator = SkipValidationDelegates.SkipAlgorithmValidation;
                    validationParameters.AudienceValidator = SkipValidationDelegates.SkipAudienceValidation;
                    validationParameters.LifetimeValidator = SkipValidationDelegates.SkipLifetimeValidation;
                    validationParameters.IssuerSigningKeyValidator = SkipValidationDelegates.SkipIssuerSigningKeyValidation;
                    validationParameters.SignatureValidator = SkipValidationDelegates.SkipSignatureValidation;
                    validationParameters.TokenReplayValidator = SkipValidationDelegates.SkipTokenReplayValidation;

                    return validationParameters;
                }
            }
        }

        public class ValidateTokenAsyncIssuerTheoryData : TheoryDataBase
        {
            public ValidateTokenAsyncIssuerTheoryData(string testId) : base(testId) { }

            internal ValidationParameters? ValidationParameters { get; set; }

            internal ExpectedException? ExpectedExceptionValidationParameters { get; set; } = ExpectedException.NoExceptionExpected;

            internal bool ExpectedIsValid { get; set; } = true;

            public bool NullTokenValidationParameters { get; internal set; } = false;

            public string? TokenIssuer { get; set; }

            public string? ValidationParametersIssuer { get; set; } = null;
        }

        private static SamlSecurityToken CreateTokenWithIssuer(string? issuer)
        {
            SamlSecurityTokenHandler samlTokenHandler = new SamlSecurityTokenHandler();

            SecurityTokenDescriptor securityTokenDescriptor = new SecurityTokenDescriptor
            {
                SigningCredentials = Default.AsymmetricSigningCredentials,
                Audience = Default.Audience,
                Issuer = issuer,
                Subject = Default.SamlClaimsIdentity
            };

            return (SamlSecurityToken)samlTokenHandler.CreateToken(securityTokenDescriptor);
        }

        private static TokenValidationParameters? CreateTokenValidationParametersForIssuerValidationOnly(
            SamlSecurityToken samlSecurityToken,
            bool nullTokenValidationParameters,
            string? validIssuer)
        {
            if (nullTokenValidationParameters)
            {
                return null;
            }

            var tokenValidationParameters = new TokenValidationParameters()
            {
                ValidateAudience = false,
                ValidateIssuer = false,
                ValidateLifetime = false,
                ValidateTokenReplay = false,
                ValidateIssuerSigningKey = false,
                IssuerSigningKey = Default.AsymmetricSigningKey,
                ValidAudiences = [Default.Audience],
                ValidIssuer = validIssuer,
                SignatureValidator = delegate (string token, TokenValidationParameters validationParameters)
                {
                    return samlSecurityToken;
                }
            };

            return tokenValidationParameters;
        }
    }
}
#nullable restore
