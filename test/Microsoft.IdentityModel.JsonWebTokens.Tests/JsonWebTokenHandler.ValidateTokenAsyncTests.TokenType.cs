// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#nullable enable
using System.Threading.Tasks;
using Microsoft.IdentityModel.TestUtils;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace Microsoft.IdentityModel.JsonWebTokens.Tests
{
    public partial class JsonWebTokenHandlerValidateTokenAsyncTests
    {
        [Theory, MemberData(nameof(ValidateTokenAsync_TokenTypeTestCases), DisableDiscoveryEnumeration = true)]
        public async Task ValidateTokenAsync_TokenType(ValidateTokenAsyncTokenTypeTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.ValidateTokenAsync_TokenType", theoryData);

            string jwtString = CreateTokenForTokenTypeValidation(theoryData.UseEmptyType, theoryData.CustomTokenType);

            await ValidateAndCompareResults(jwtString, theoryData, context);

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<ValidateTokenAsyncTokenTypeTheoryData> ValidateTokenAsync_TokenTypeTestCases
        {
            get
            {
                var theoryData = new TheoryData<ValidateTokenAsyncTokenTypeTheoryData>();

                theoryData.Add(new ValidateTokenAsyncTokenTypeTheoryData("Valid_JwtToken")
                {
                    TokenValidationParameters = CreateTokenValidationParameters(),
                    ValidationParameters = CreateValidationParameters(),
                });

                theoryData.Add(new ValidateTokenAsyncTokenTypeTheoryData("Valid_UnknownTokenType_NoValidTokenTypes")
                {
                    // If there are no valid token types, any token type is valid
                    CustomTokenType = "SomeUnknownType",
                    TokenValidationParameters = CreateTokenValidationParameters(null),
                    ValidationParameters = CreateValidationParameters(null),
                });

                theoryData.Add(new ValidateTokenAsyncTokenTypeTheoryData("Valid_CustomToken_AddedAsValidTokenType")
                {
                    CustomTokenType = "PPT",
                    TokenValidationParameters = CreateTokenValidationParameters(validTokenType: "PPT"),
                    ValidationParameters = CreateValidationParameters(validTokenType: "PPT"),
                });

                theoryData.Add(new ValidateTokenAsyncTokenTypeTheoryData("Invalid_CustomToken_NotAddedAsValidTokenType")
                {
                    CustomTokenType = "PPT",
                    TokenValidationParameters = CreateTokenValidationParameters(),
                    ValidationParameters = CreateValidationParameters(),
                    ExpectedIsValid = false,
                    ExpectedException = ExpectedException.SecurityTokenInvalidTypeException("IDX10257:"),
                });

                theoryData.Add(new ValidateTokenAsyncTokenTypeTheoryData("Invalid_EmptyTokenType")
                {
                    UseEmptyType = true,
                    TokenValidationParameters = CreateTokenValidationParameters(),
                    ValidationParameters = CreateValidationParameters(),
                    ExpectedIsValid = false,
                    ExpectedException = ExpectedException.SecurityTokenInvalidTypeException("IDX10256:"),
                });

                return theoryData;

                static TokenValidationParameters CreateTokenValidationParameters(string? validTokenType = "JWT")
                {
                    // only validate the signature and issuer signing key
                    var tokenValidationParameters = new TokenValidationParameters()
                    {
                        ValidateAudience = false,
                        ValidateIssuer = false,
                        ValidateLifetime = false,
                        ValidateTokenReplay = false,
                        ValidateIssuerSigningKey = false,
                        RequireSignedTokens = false,
                    };

                    if (validTokenType is not null)
                        tokenValidationParameters.ValidTypes = [validTokenType];

                    return tokenValidationParameters;
                }

                static ValidationParameters CreateValidationParameters(string? validTokenType = "JWT")
                {
                    ValidationParameters validationParameters = new ValidationParameters();

                    // Skip all validations except token type
                    validationParameters.AlgorithmValidator = SkipValidationDelegates.SkipAlgorithmValidation;
                    validationParameters.AudienceValidator = SkipValidationDelegates.SkipAudienceValidation;
                    validationParameters.IssuerSigningKeyValidator = SkipValidationDelegates.SkipIssuerSigningKeyValidation;
                    validationParameters.IssuerValidatorAsync = SkipValidationDelegates.SkipIssuerValidation;
                    validationParameters.LifetimeValidator = SkipValidationDelegates.SkipLifetimeValidation;
                    validationParameters.SignatureValidator = SkipValidationDelegates.SkipSignatureValidation;
                    validationParameters.TokenReplayValidator = SkipValidationDelegates.SkipTokenReplayValidation;

                    if (validTokenType is not null)
                        validationParameters.ValidTypes.Add(validTokenType);

                    return validationParameters;
                }
            }
        }

        public class ValidateTokenAsyncTokenTypeTheoryData : ValidateTokenAsyncBaseTheoryData
        {
            public ValidateTokenAsyncTokenTypeTheoryData(string testId) : base(testId) { }

            public bool UseEmptyType { get; set; } = false;

            public string? CustomTokenType { get; set; } = null;
        }

        // Custom JWT with empty string for type
        private static string emptyTypeJWT = "eyJ0eXAiOiIiLCJhbGciOiJub25lIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTcyOTY5NDI1OCwiZXhwIjoxNzI5Njk3ODU4fQ.";

        private static string CreateTokenForTokenTypeValidation(bool useEmptyType = false, string? tokenType = null)
        {
            if (useEmptyType)
                return emptyTypeJWT;

            JsonWebTokenHandler jsonWebTokenHandler = new JsonWebTokenHandler();

            SecurityTokenDescriptor securityTokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = Default.ClaimsIdentity,
                TokenType = tokenType ?? "JWT",
            };

            return jsonWebTokenHandler.CreateToken(securityTokenDescriptor);
        }
    }
}
#nullable restore
