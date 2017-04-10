//------------------------------------------------------------------------------
//
// Copyright (c) Microsoft Corporation.
// All rights reserved.
//
// This code is licensed under the MIT License.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files(the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and / or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions :
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
//
//------------------------------------------------------------------------------

using System;
using System.Collections.Generic;
using Microsoft.IdentityModel.Tokens.Tests;
using Xunit;

namespace Microsoft.IdentityModel.Tokens.Saml.Tests
{
    public class ValidateTheoryData
    {
        public static void AddValidateAudienceTheoryData(TheoryData<CreateAndValidateTheoryData> theoryData, SecurityTokenHandler handler)
        {
            theoryData.Add(new CreateAndValidateTheoryData
            {
                Audiences = new List<string>(),
                First = true,
                ExpectedException = ExpectedException.ArgumentNullException("IDX10000:"),
                Handler = handler,
                TestId = "TokenValidationParameters null",
                ValidationParameters = null,
            });

            theoryData.Add(new CreateAndValidateTheoryData
            {
                Audiences = new List<string>(),
                Handler = handler,
                TestId = "ValidateAudience = false",
                ValidationParameters = new TokenValidationParameters
                {
                    ValidateAudience = false,
                },
            });

            theoryData.Add(new CreateAndValidateTheoryData
            {
                Audiences = new List<string>(),
                ExpectedException = ExpectedException.SecurityTokenInvalidAudienceException("IDX10208:"),
                Handler = handler,
                TestId = "no audiences in validationParameters",
                ValidationParameters = new TokenValidationParameters
                {
                    ValidateAudience = true,
                },
            });

            theoryData.Add(new CreateAndValidateTheoryData
            {
                Audiences = new List<string> { "John" },
                ExpectedException = ExpectedException.SecurityTokenInvalidAudienceException("IDX10208:"),
                Handler = handler,
                TestId = "audience has value, tvp has no values",
                ValidationParameters = new TokenValidationParameters
                {
                    ValidateAudience = true,
                },
            });

            theoryData.Add(new CreateAndValidateTheoryData
            {
                Audiences = new List<string> { "John" },
                ExpectedException = ExpectedException.SecurityTokenInvalidAudienceException("IDX10214:"),
                Handler = handler,
                TestId = "audience not matched",
                ValidationParameters = new TokenValidationParameters
                {
                    ValidateAudience = true,
                    ValidAudience = "frank"
                },
            });

            theoryData.Add(new CreateAndValidateTheoryData
            {
                Audiences = new List<string> { "John" },
                Handler = handler,
                TestId = "AudienceValidator returns true",
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

            theoryData.Add(new CreateAndValidateTheoryData
            {
                Audiences = new List<string> { "John" },
                Handler = handler,
                TestId = "AudienceValidator throws, validateAudience false",
                ValidationParameters = new TokenValidationParameters
                {
                    AudienceValidator = IdentityUtilities.AudienceValidatorThrows,
                    ValidateAudience = false,
                    ValidAudience = "frank"
                },
            });
        }

        public static void AddValidateIssuerTheoryData(TheoryData<CreateAndValidateTheoryData> theoryData, SecurityTokenHandler handler)
        {
            theoryData.Add(new CreateAndValidateTheoryData
            {
                ExpectedException = ExpectedException.ArgumentNullException("IDX10000:"),
                First = true,
                Handler = handler,
                Issuer = "bob",
                TestId = "ValidationParameters null",
                ValidationParameters = null,
            });

            theoryData.Add(new CreateAndValidateTheoryData
            {
                Handler = handler,
                TestId = "ValidateIssuer == false",
                ValidationParameters = new TokenValidationParameters { ValidateIssuer = false },
            });

            theoryData.Add(new CreateAndValidateTheoryData
            {
                ExpectedException = ExpectedException.SecurityTokenInvalidIssuerException("IDX10205:"),
                Handler = handler,
                Issuer = "bob",
                TestId = "Issuer not matched",
                ValidationParameters = new TokenValidationParameters { ValidIssuer = "frank" }
            });

            theoryData.Add(new CreateAndValidateTheoryData
            {
                Handler = handler,
                Issuer = "bob",
                TestId = "Issuer matched",
                ValidationParameters = new TokenValidationParameters
                {
                    ValidateAudience = false,
                    ValidIssuer = "bob"
                }
            });

            theoryData.Add(new CreateAndValidateTheoryData
            {
                ExpectedException = ExpectedException.SecurityTokenInvalidIssuerException(substringExpected: "IDX10205:"),
                Handler = handler,
                Issuer = "bob",
                TestId = "ValidIssuers set but not matched",
                ValidationParameters = new TokenValidationParameters
                {
                    ValidateAudience = false,
                    ValidIssuers = new List<string> { "john", "paul", "george", "ringo" }
                }
            });

            theoryData.Add(new CreateAndValidateTheoryData
            {
                Handler = handler,
                Issuer = "bob",
                TestId = "IssuerValidator - echo",
                ValidationParameters = new TokenValidationParameters
                {
                    IssuerValidator = IdentityUtilities.IssuerValidatorEcho,
                    ValidateAudience = false
                }
            });
        }
    }

    public class CreateAndValidateTheoryData : TheoryDataBase
    {
        public string Actor { get; set; }

        public TokenValidationParameters ActorTokenValidationParameters { get; set; }

        public bool CanRead { get; set; }

        public SecurityToken CompareTo { get; set; }

        public Type ExceptionType { get; set; }

        public SecurityTokenHandler Handler { get; set; }

        public string Issuer { get; set; }

        public IEnumerable<string> Audiences { get; set; }

        public SecurityTokenDescriptor TokenDescriptor { get; set; }

        public string Token { get; set; }

        public TokenValidationParameters ValidationParameters { get; set; }

        public override string ToString()
        {
            return $"{TestId}, {Token}, {ExpectedException}";
        }
    }

}
