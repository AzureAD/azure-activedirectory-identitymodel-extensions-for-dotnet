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
using System.Security.Claims;
using Microsoft.IdentityModel.Tokens.Saml2;
using Microsoft.IdentityModel.Tokens.Tests;
using Xunit;

namespace Microsoft.IdentityModel.Tokens.Saml.Tests
{
    public class CreateAndValidateParams
    {
        public string Actor { get; set; }

        public TokenValidationParameters ActorTokenValidationParameters { get; set; }

        public bool CanRead { get; set; }

        public SecurityToken CompareTo { get; set; }

        public ExpectedException ExpectedException { get; set; }

        public Type ExceptionType { get; set; }

        public Saml2SecurityTokenHandler Handler { get; set; }

        public string Issuer { get; set; }

        public IEnumerable<string> Audiences { get; set; }

        public SecurityTokenDescriptor TokenDescriptor { get; set; }

        public string TestId { get; set; }

        public string Token { get; set; }

        public TokenValidationParameters ValidationParameters { get; set; }

        public override string ToString()
        {
            return $"{TestId}, {Token}, {ExpectedException}";
        }
    }

    public class Saml2SecurityTokenHandlerTests
    {
        private static bool _firstValidateToken = true;
        private static bool _firstValidateIssuer = true;
        private static bool _firstValidateAudience = true;

        [Fact]
        public void Constructors()
        {
            Saml2SecurityTokenHandler saml2SecurityTokenHandler = new Saml2SecurityTokenHandler();
        }

        [Fact]
        public void Defaults()
        {
            Saml2SecurityTokenHandler samlSecurityTokenHandler = new Saml2SecurityTokenHandler();
            Assert.True(samlSecurityTokenHandler.MaximumTokenSizeInBytes == TokenValidationParameters.DefaultMaximumTokenSizeInBytes, "MaximumTokenSizeInBytes");
        }

        [Fact]
        public void GetSets()
        {
            Saml2SecurityTokenHandler samlSecurityTokenHandler = new Saml2SecurityTokenHandler();
            TestUtilities.SetGet(samlSecurityTokenHandler, "MaximumTokenSizeInBytes", (object)0, ExpectedException.ArgumentOutOfRangeException("IDX11010:"));
            TestUtilities.SetGet(samlSecurityTokenHandler, "MaximumTokenSizeInBytes", (object)1, ExpectedException.NoExceptionExpected);
        }

#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant
        [Theory, MemberData("CanReadTokenTheoryData")]
#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
        public void CanReadToken(CreateAndValidateParams theoryData)
        {
            if (theoryData.CanRead != theoryData.Handler.CanReadToken(theoryData.Token))
            {
                Assert.False(false, $"Expected CanRead != CanRead, token: {theoryData.Token}");
            }
        }

        public static TheoryData<CreateAndValidateParams> CanReadTokenTheoryData
        {
            get
            {
                var theoryData = new TheoryData<CreateAndValidateParams>();
                
                // CanReadToken
                var handler = new Saml2SecurityTokenHandler();
                theoryData.Add(
                    new CreateAndValidateParams
                    {
                        CanRead = false,
                        Handler = handler,
                        TestId = "Null Token",
                        Token = null
                    });

                theoryData.Add(
                    new CreateAndValidateParams
                    {
                        CanRead = false,
                        Handler = handler,
                        TestId = "DefaultMaximumTokenSizeInBytes + 1",
                        Token = new string('S', TokenValidationParameters.DefaultMaximumTokenSizeInBytes + 2)
                    });

                theoryData.Add(
                    new CreateAndValidateParams
                    {
                        CanRead = true,
                        Handler = handler,
                        TestId = "AADSaml2Token",
                        Token = RefrenceSaml2Token.SamlToken
                    });

                //samlString = IdentityUtilities.CreateSamlToken();
                //Assert.False(CanReadToken(securityToken: samlString, samlSecurityTokenHandler: samlSecurityTokenHandler, expectedException: ExpectedException.NoExceptionExpected));

                //samlString = IdentityUtilities.CreateSaml2Token();
                //Assert.True(CanReadToken(securityToken: samlString, samlSecurityTokenHandler: samlSecurityTokenHandler, expectedException: ExpectedException.NoExceptionExpected));

                return theoryData;
            }
        }

#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant
        [Theory, MemberData("ValidateAudienceTheoryData")]
#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
        public void ValidateAudience(CreateAndValidateParams theoryData)
        {
            TestUtilities.TestHeader("Saml2SecurityTokenHandlerTests.ValidateAudience", theoryData.TestId, ref _firstValidateAudience);
            try
            {
                // TODO - need to pass actual Saml2Token
                ((theoryData.Handler)as DerivedSamlSecurityTokenHandler).ValidateAudiencePublic(theoryData.Audiences, null, theoryData.ValidationParameters);
                theoryData.ExpectedException.ProcessNoException();
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex);
            }
        }

        public static TheoryData<CreateAndValidateParams> ValidateAudienceTheoryData
        {
            get
            {
                var theoryData = new TheoryData<CreateAndValidateParams>();
                var handler = new DerivedSamlSecurityTokenHandler();

                theoryData.Add(
                    new CreateAndValidateParams
                    {
                        Audiences = new List<string>(),
                        ExpectedException = ExpectedException.ArgumentNullException("IDX10000:"),
                        Handler = handler,
                        TestId = "'TokenValidationParameters null'",
                        ValidationParameters = null,
                    });

                theoryData.Add(
                    new CreateAndValidateParams
                    {
                        Audiences = new List<string>(),
                        ExpectedException = ExpectedException.NoExceptionExpected,
                        Handler = handler,
                        TestId = "'ValidateAudience = false'",
                        ValidationParameters = new TokenValidationParameters
                        {
                            ValidateAudience = false,
                        },
                    });

                theoryData.Add(
                    new CreateAndValidateParams
                    {
                        Audiences = new List<string>(),
                        ExpectedException = ExpectedException.SecurityTokenInvalidAudienceException("IDX10208:"),
                        Handler = handler,
                        TestId = "'no audiences in validationParameters",
                        ValidationParameters = new TokenValidationParameters
                        {
                            ValidateAudience = true,
                        },
                    });

                theoryData.Add(
                    new CreateAndValidateParams
                    {
                        Audiences = new List<string> { "John" },
                        ExpectedException = ExpectedException.SecurityTokenInvalidAudienceException("IDX10208:"),
                        Handler = handler,
                        TestId = "'audience has value, tvp has no values'",
                        ValidationParameters = new TokenValidationParameters
                        {
                            ValidateAudience = true,
                        },
                    });

                theoryData.Add(
                    new CreateAndValidateParams
                    {
                        Audiences = new List<string> { "John" },
                        ExpectedException = ExpectedException.SecurityTokenInvalidAudienceException("IDX10214:"),
                        Handler = handler,
                        TestId = "'audience not matched'",
                        ValidationParameters = new TokenValidationParameters
                        {
                            ValidateAudience = true,
                            ValidAudience = "frank"
                        },
                    });

                theoryData.Add(
                    new CreateAndValidateParams
                    {
                        Audiences = new List<string> { "John" },
                        ExpectedException = ExpectedException.NoExceptionExpected,
                        Handler = handler,
                        TestId = "'AudienceValidator returns true'",
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

                theoryData.Add(
                    new CreateAndValidateParams
                    {
                        Audiences = new List<string> { "John" },
                        ExpectedException = ExpectedException.NoExceptionExpected,
                        Handler = handler,
                        TestId = "'AudienceValidator throws, validateAudience false'",
                        ValidationParameters = new TokenValidationParameters
                        {
                            AudienceValidator = IdentityUtilities.AudienceValidatorThrows,
                            ValidateAudience = false,
                            ValidAudience = "frank"
                        },
                    });

                return theoryData;
            }
        }

#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant
        [Theory, MemberData("ValidateIssuerTheoryData")]
#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
        public void ValidateIssuer(CreateAndValidateParams theoryData)
        {
            TestUtilities.TestHeader("Saml2SecurityTokenHandlerTests.ValidateIssuer", theoryData.TestId, ref _firstValidateIssuer);
            try
            {
                // TODO - need to pass actual Saml2Token
                ((theoryData.Handler)as DerivedSamlSecurityTokenHandler).ValidateIssuerPublic(theoryData.Issuer, null, theoryData.ValidationParameters);
                theoryData.ExpectedException.ProcessNoException();
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex);
            }
        }

        public static TheoryData<CreateAndValidateParams> ValidateIssuerTheoryData
        {
            get
            {
                var theoryData = new TheoryData<CreateAndValidateParams>();
                var handler = new DerivedSamlSecurityTokenHandler();

                theoryData.Add(
                    new CreateAndValidateParams
                    {
                        ExpectedException = ExpectedException.ArgumentNullException("IDX10000:"),
                        Handler = handler,
                        Issuer = "bob",
                        TestId = "'ValidationParameters null'",
                        ValidationParameters = null,
                    });

                theoryData.Add(
                    new CreateAndValidateParams
                    {
                        ExpectedException = ExpectedException.NoExceptionExpected,
                        Handler = handler,
                        TestId = "'ValidateIssuer == false'",
                        ValidationParameters = new TokenValidationParameters { ValidateIssuer = false },
                    });

                theoryData.Add(
                    new CreateAndValidateParams
                    {
                        ExpectedException = ExpectedException.SecurityTokenInvalidIssuerException("IDX10205:"),
                        Handler = handler,
                        Issuer = "bob",
                        TestId = "'Issuer not matched'",
                        ValidationParameters = new TokenValidationParameters { ValidIssuer = "frank" }
                    });

                theoryData.Add(
                    new CreateAndValidateParams
                    {
                        ExpectedException = ExpectedException.NoExceptionExpected,
                        Handler = handler,
                        Issuer = "bob",
                        TestId = "'Issuer matched'",
                        ValidationParameters = new TokenValidationParameters
                        {
                            ValidateAudience = false,
                            ValidIssuer = "bob"
                        }
                    });

                theoryData.Add(
                    new CreateAndValidateParams
                    {
                        ExpectedException = ExpectedException.SecurityTokenInvalidIssuerException(substringExpected: "IDX10205:"),
                        Handler = handler,
                        Issuer = "bob",
                        TestId = "'ValidIssuers set but not matched'",
                        ValidationParameters = new TokenValidationParameters
                        {
                            ValidateAudience = false,
                            ValidIssuers = new List<string> { "john", "paul", "george", "ringo" }
                        }
                    });

                theoryData.Add(
                    new CreateAndValidateParams
                    {
                        ExpectedException = ExpectedException.NoExceptionExpected,
                        Handler = handler,
                        Issuer = "bob",
                        TestId = "'IssuerValidator - echo'",
                        ValidationParameters = new TokenValidationParameters
                        {
                            IssuerValidator = IdentityUtilities.IssuerValidatorEcho,
                            ValidateAudience = false
                        }
                    });

                return theoryData;
            }
        }

#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant
        [Theory, MemberData("ValidateTokenTheoryData")]
#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
        public void ValidateToken(CreateAndValidateParams theoryData)
        {
            TestUtilities.TestHeader("Saml2SecurityTokenHandlerTests.ValidateToken", theoryData.TestId, ref _firstValidateToken);

            ClaimsPrincipal retVal = null;
            try
            {
                SecurityToken validatedToken;
                retVal = theoryData.Handler.ValidateToken(theoryData.Token, theoryData.ValidationParameters, out validatedToken);
                theoryData.ExpectedException.ProcessNoException();
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex);
            }
        }

        public static TheoryData<CreateAndValidateParams> ValidateTokenTheoryData
        {
            get
            {
                var theoryData = new TheoryData<CreateAndValidateParams>();

                var tokenHandler = new Saml2SecurityTokenHandler();
                theoryData.Add(
                    new CreateAndValidateParams
                    {
                        ExpectedException = ExpectedException.ArgumentNullException("IDX10000:"),
                        Handler = tokenHandler,
                        TestId = "Null-SecurityToken",
                        Token = null,
                        ValidationParameters = new TokenValidationParameters()
                    });

                theoryData.Add(
                    new CreateAndValidateParams
                    {
                        ExpectedException = ExpectedException.ArgumentNullException("IDX10000:"),
                        Handler = tokenHandler,
                        TestId = "NULL-TokenValidationParameters",
                        Token = "s",
                        ValidationParameters = null,
                    });

                tokenHandler = new Saml2SecurityTokenHandler();
                tokenHandler.MaximumTokenSizeInBytes = 1;
                theoryData.Add(
                    new CreateAndValidateParams
                    {
                        ExpectedException = ExpectedException.ArgumentException("IDX11013:"),
                        Handler = tokenHandler,
                        TestId = "SecurityTokenTooLarge",
                        Token = "ss",
                        ValidationParameters = new TokenValidationParameters(),
                    });

                //tokenHandler = new Saml2SecurityTokenHandler();
                //string samlToken = IdentityUtilities.CreateSaml2Token();
                //theoryData.Add(
                //    new CreateAndValidateParams
                //    {
                //        ExpectedException = ExpectedException.NoExceptionExpected,
                //        SecurityTokenHandler = tokenHandler,
                //        TestId = "Valid-Saml2SecurityToken",
                //        Token = samlToken,
                //        TokenValidationParameters = IdentityUtilities.DefaultAsymmetricTokenValidationParameters,
                //    });

                return theoryData;
            }
        }

        private class DerivedSamlSecurityTokenHandler : Saml2SecurityTokenHandler
        {
            public string ValidateIssuerPublic(string issuer, SecurityToken token, TokenValidationParameters validationParameters)
            {
                return base.ValidateIssuer(issuer, token, validationParameters);
            }

            public void ValidateAudiencePublic(IEnumerable<string> audiences, SecurityToken token, TokenValidationParameters validationParameters)
            {
                base.ValidateAudience(audiences, token, validationParameters);
            }
        }

        private class DerivedSaml2SecurityToken : Saml2SecurityToken
        {
            public DerivedSaml2SecurityToken(Saml2Assertion assertion)
                : base(assertion)
            { }
        }
    }
}
