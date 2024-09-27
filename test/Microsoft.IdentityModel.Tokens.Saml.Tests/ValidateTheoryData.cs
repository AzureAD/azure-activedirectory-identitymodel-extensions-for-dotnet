// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System.Collections.Generic;
using Microsoft.IdentityModel.TestUtils;

namespace Microsoft.IdentityModel.Tokens.Saml.Tests
{
    public class ValidateTheoryData
    {
        public static void AddValidateAudienceTheoryData(List<TokenTheoryData> theoryData)
        {
            theoryData.Add(new TokenTheoryData
            {
                Audiences = new List<string>(),
                First = true,
                ExpectedException = ExpectedException.ArgumentNullException("IDX10000:"),
                TestId = "TokenValidationParameters_Null",
                ValidationParameters = null,
            });

            theoryData.Add(new TokenTheoryData
            {
                Audiences = new List<string>(),
                TestId = "ValidateAudience_Equals_False",
                ValidationParameters = new TokenValidationParameters
                {
                    ValidateAudience = false,
                },
            });

            theoryData.Add(new TokenTheoryData
            {
                Audiences = new List<string>(),
                ExpectedException = ExpectedException.SecurityTokenInvalidAudienceException("IDX10208:"),
                TestId = "No_Audiences_In_TokenValidationParameters",
                ValidationParameters = new TokenValidationParameters
                {
                    ValidateAudience = true,
                },
            });

            theoryData.Add(new TokenTheoryData
            {
                Audiences = new List<string> { "John" },
                ExpectedException = ExpectedException.SecurityTokenInvalidAudienceException("IDX10208:"),
                TestId = "Audience_Has_Value_TVP_Has_No_Values",
                ValidationParameters = new TokenValidationParameters
                {
                    ValidateAudience = true,
                },
            });

            theoryData.Add(new TokenTheoryData
            {
                Audiences = new List<string> { "John" },
                ExpectedException = ExpectedException.SecurityTokenInvalidAudienceException("IDX10214:"),
                TestId = "Audience_Not_Matched",
                ValidationParameters = new TokenValidationParameters
                {
                    ValidateAudience = true,
                    ValidAudience = "frank"
                },
            });

            theoryData.Add(new TokenTheoryData
            {
                Audiences = new List<string> { "John" },
                TestId = "AudienceValidator_Returns_True",
                ValidationParameters = new TokenValidationParameters
                {
                    AudienceValidator = (aud, token, type) =>
                    {
                        return true;
                    },
                    ValidateAudience = true,
                    ValidAudience = "frank"
                },
            });

            theoryData.Add(new TokenTheoryData
            {
                Audiences = new List<string> { "John" },
                ExpectedException = ExpectedException.SecurityTokenInvalidAudienceException(),
                TestId = "AudienceValidator_Throws_ValidateAudience_False",
                ValidationParameters = new TokenValidationParameters
                {
                    AudienceValidator = ValidationDelegates.AudienceValidatorThrows,
                    ValidateAudience = false,
                    ValidAudience = "frank"
                },
            });
        }

        public static void AddValidateIssuerTheoryData(List<TokenTheoryData> theoryData)
        {
            theoryData.Add(new TokenTheoryData
            {
                ExpectedException = ExpectedException.ArgumentNullException("IDX10000:"),
                First = true,
                Issuer = "bob",
                TestId = "TokenValidationParameters_Null",
                ValidationParameters = null,
            });

            theoryData.Add(new TokenTheoryData
            {
                TestId = "ValidateIssuer_Equals_False",
                ValidationParameters = new TokenValidationParameters { ValidateIssuer = false },
            });

            theoryData.Add(new TokenTheoryData
            {
                ExpectedException = ExpectedException.SecurityTokenInvalidIssuerException("IDX10205:"),
                Issuer = "bob",
                TestId = "Issuer_Not_Matched",
                ValidationParameters = new TokenValidationParameters { ValidIssuer = "frank" }
            });

            theoryData.Add(new TokenTheoryData
            {
                Issuer = "bob",
                TestId = "Issuer_Matched",
                ValidationParameters = new TokenValidationParameters
                {
                    ValidateAudience = false,
                    ValidIssuer = "bob"
                }
            });

            theoryData.Add(new TokenTheoryData
            {
                ExpectedException = ExpectedException.SecurityTokenInvalidIssuerException(substringExpected: "IDX10205:"),
                Issuer = "bob",
                TestId = "ValidIssuers_Set_But_Not_Matched",
                ValidationParameters = new TokenValidationParameters
                {
                    ValidateAudience = false,
                    ValidIssuers = new List<string> { "john", "paul", "george", "ringo" }
                }
            });

            theoryData.Add(new TokenTheoryData
            {
                Issuer = "bob",
                TestId = "IssuerValidator_Echo",
                ValidationParameters = new TokenValidationParameters
                {
                    IssuerValidator = ValidationDelegates.IssuerValidatorEcho,
                    ValidateAudience = false
                }
            });
        }
    }
}
