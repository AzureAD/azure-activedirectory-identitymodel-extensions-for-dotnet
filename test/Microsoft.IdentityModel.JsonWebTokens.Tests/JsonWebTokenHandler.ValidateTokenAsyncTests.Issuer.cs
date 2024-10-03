// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#nullable enable
using System.Threading.Tasks;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.TestUtils;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace Microsoft.IdentityModel.JsonWebTokens.Tests
{
    public partial class JsonWebTokenHandlerValidateTokenAsyncTests
    {
        [Theory, MemberData(nameof(ValidateTokenAsync_IssuerTestCases))]
        public async Task ValidateTokenAsync_Issuer(ValidateTokenAsyncIssuerTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.ValidateTokenAsync_Issuer", theoryData);

            string jwtString = CreateTokenWithIssuer(theoryData.TokenIssuer);

            await ValidateAndCompareResults(jwtString, theoryData, context);

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<ValidateTokenAsyncIssuerTheoryData> ValidateTokenAsync_IssuerTestCases
        {
            get
            {
                return new TheoryData<ValidateTokenAsyncIssuerTheoryData>
                {
                    new ValidateTokenAsyncIssuerTheoryData("Valid_IssuerIsValidIssuer")
                    {
                        TokenIssuer = Default.Issuer,
                        TokenValidationParameters = CreateTokenValidationParameters(validIssuer: Default.Issuer),
                        ValidationParameters = CreateValidationParameters(validIssuer: Default.Issuer),
                    },
                    new ValidateTokenAsyncIssuerTheoryData("Valid_IssuerIsConfigurationIssuer")
                    {
                        TokenIssuer = Default.Issuer,
                        TokenValidationParameters = CreateTokenValidationParameters(configurationIssuer: Default.Issuer),
                        ValidationParameters = CreateValidationParameters(configurationIssuer: Default.Issuer),
                    },
                    new ValidateTokenAsyncIssuerTheoryData("Invalid_IssuerIsNotValid")
                    {
                        TokenIssuer = "InvalidIssuer",
                        TokenValidationParameters = CreateTokenValidationParameters(validIssuer: Default.Issuer),
                        ValidationParameters = CreateValidationParameters(validIssuer: Default.Issuer),
                        ExpectedIsValid = false,
                        ExpectedException = new ExpectedException(typeof(SecurityTokenInvalidIssuerException), "IDX10205:"),
                        ExpectedExceptionValidationParameters = new ExpectedException(typeof(SecurityTokenInvalidIssuerException), "IDX10212:"),
                    },
                    new ValidateTokenAsyncIssuerTheoryData("Invalid_IssuerIsNull")
                    {
                        TokenIssuer = null,
                        TokenValidationParameters = CreateTokenValidationParameters(validIssuer: Default.Issuer),
                        ValidationParameters = CreateValidationParameters(validIssuer: Default.Issuer),
                        ExpectedIsValid = false,
                        ExpectedException = new ExpectedException(typeof(SecurityTokenInvalidIssuerException), "IDX10211:"),
                    },
                    new ValidateTokenAsyncIssuerTheoryData("Invalid_IssuerIsEmpty")
                    {
                        TokenIssuer = string.Empty,
                        TokenValidationParameters = CreateTokenValidationParameters(validIssuer: Default.Issuer),
                        ValidationParameters = CreateValidationParameters(validIssuer: Default.Issuer),
                        ExpectedIsValid = false,
                        ExpectedException = new ExpectedException(typeof(SecurityTokenInvalidIssuerException), "IDX10211:"),
                    },
                    new ValidateTokenAsyncIssuerTheoryData("Invalid_NoValidIssuersProvided")
                                        {
                        TokenIssuer = Default.Issuer,
                        TokenValidationParameters = CreateTokenValidationParameters(),
                        ValidationParameters = CreateValidationParameters(),
                        ExpectedIsValid = false,
                        ExpectedException = new ExpectedException(typeof(SecurityTokenInvalidIssuerException), "IDX10204:"),
                        ExpectedExceptionValidationParameters = new ExpectedException(typeof(SecurityTokenInvalidIssuerException), "IDX10211:"),
                    },
                };

                static TokenValidationParameters CreateTokenValidationParameters(
                    string? validIssuer = null, string? configurationIssuer = null)
                {
                    var tokenValidationParameters = new TokenValidationParameters
                    {
                        ValidateAudience = true,
                        ValidateIssuer = true,
                        ValidateLifetime = true,
                        ValidateTokenReplay = true,
                        ValidateIssuerSigningKey = true,
                        IssuerSigningKey = Default.AsymmetricSigningKey,
                        ValidAudiences = [Default.Audience],
                        ValidIssuer = validIssuer
                    };

                    if (configurationIssuer is not null)
                    {
                        var validConfig = new OpenIdConnectConfiguration() { Issuer = configurationIssuer };
                        tokenValidationParameters.ConfigurationManager = new MockConfigurationManager<OpenIdConnectConfiguration>(validConfig);
                    }

                    return tokenValidationParameters;
                }

                static ValidationParameters CreateValidationParameters(
                    string? validIssuer = null, string? configurationIssuer = null)
                {
                    ValidationParameters validationParameters = new ValidationParameters();
                    validationParameters.ValidAudiences.Add(Default.Audience);
                    validationParameters.IssuerSigningKeys.Add(Default.AsymmetricSigningKey);

                    if (configurationIssuer is not null)
                    {
                        var validConfig = new OpenIdConnectConfiguration() { Issuer = configurationIssuer };
                        validationParameters.ConfigurationManager = new MockConfigurationManager<OpenIdConnectConfiguration>(validConfig);
                    }

                    if (validIssuer is not null)
                        validationParameters.ValidIssuers.Add(validIssuer);

                    return validationParameters;
                }
            }
        }

        public class ValidateTokenAsyncIssuerTheoryData : ValidateTokenAsyncBaseTheoryData
        {
            public ValidateTokenAsyncIssuerTheoryData(string testId) : base(testId) { }

            public string? TokenIssuer { get; set; }
        }

        private static string CreateTokenWithIssuer(string? issuer)
        {
            JsonWebTokenHandler jsonWebTokenHandler = new JsonWebTokenHandler();

            SecurityTokenDescriptor securityTokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = Default.ClaimsIdentity,
                SigningCredentials = Default.AsymmetricSigningCredentials,
                Audience = Default.Audience,
                Issuer = issuer,
            };

            return jsonWebTokenHandler.CreateToken(securityTokenDescriptor);
        }
    }
}
#nullable restore
