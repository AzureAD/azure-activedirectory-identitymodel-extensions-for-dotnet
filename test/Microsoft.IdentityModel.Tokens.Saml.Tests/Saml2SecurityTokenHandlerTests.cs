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
using System.IdentityModel.Tokens;
using System.Security.Claims;
using Microsoft.IdentityModel.Tokens.Tests;
using Xunit;

namespace Microsoft.IdentityModel.Tokens.Saml.Tests
{
    public class CreateAndValidateParams
    {
        public string Actor { get; set; }

        public TokenValidationParameters ActorTokenValidationParameters { get; set; }

        public string TestId { get; set; }

        public SecurityToken CompareTo { get; set; }

        public ExpectedException ExpectedException { get; set; }

        public Type ExceptionType { get; set; }

        public string Token { get; set; }

        public Saml2SecurityTokenHandler SecurityTokenHandler { get; set; }

        public SecurityTokenDescriptor SecurityTokenDescriptor { get; set; }

        public TokenValidationParameters TokenValidationParameters { get; set; }
    }

    /// <summary>
    /// 
    /// </summary>
    public class Saml2SecurityTokenHandlerTests
    {
        private static bool _firstValidateToken = true;

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
            TestUtilities.SetGet(samlSecurityTokenHandler, "MaximumTokenSizeInBytes", (object)0, ExpectedException.ArgumentOutOfRangeException(substringExpected: "IDX10101"));
            TestUtilities.SetGet(samlSecurityTokenHandler, "MaximumTokenSizeInBytes", (object)1, ExpectedException.NoExceptionExpected);
        }

        [Fact (Skip ="till 5.2.0")]
        public void Publics()
        {
            //CanReadToken();
            ValidateAudience();
            ValidateIssuer();
        }

        private void CanReadToken()
        {
            // CanReadToken
            Saml2SecurityTokenHandler samlSecurityTokenHandler = new Saml2SecurityTokenHandler();
            Assert.False(CanReadToken(securityToken: null, samlSecurityTokenHandler: samlSecurityTokenHandler, expectedException: ExpectedException.NoExceptionExpected));

            string samlString = new string('S', TokenValidationParameters.DefaultMaximumTokenSizeInBytes + 1);
            Assert.False(CanReadToken(samlString, samlSecurityTokenHandler, ExpectedException.NoExceptionExpected));

            samlString = new string('S', TokenValidationParameters.DefaultMaximumTokenSizeInBytes);
            CanReadToken(securityToken: samlString, samlSecurityTokenHandler: samlSecurityTokenHandler, expectedException: ExpectedException.NoExceptionExpected);

            //samlString = IdentityUtilities.CreateSamlToken();
            //Assert.False(CanReadToken(securityToken: samlString, samlSecurityTokenHandler: samlSecurityTokenHandler, expectedException: ExpectedException.NoExceptionExpected));

            //samlString = IdentityUtilities.CreateSaml2Token();
            //Assert.True(CanReadToken(securityToken: samlString, samlSecurityTokenHandler: samlSecurityTokenHandler, expectedException: ExpectedException.NoExceptionExpected));
        }

        private bool CanReadToken(string securityToken, Saml2SecurityTokenHandler samlSecurityTokenHandler, ExpectedException expectedException)
        {
            bool canReadToken = false;
            try
            {
                canReadToken = samlSecurityTokenHandler.CanReadToken(securityToken);
                expectedException.ProcessNoException();
            }
            catch (Exception exception)
            {
                expectedException.ProcessException(exception);
            }

            return canReadToken;
        }

        private void ValidateIssuer()
        {
            DerivedSamlSecurityTokenHandler samlSecurityTokenHandler = new DerivedSamlSecurityTokenHandler();

            ExpectedException expectedException = ExpectedException.NoExceptionExpected;
            ValidateIssuer(null, new TokenValidationParameters { ValidateIssuer = false }, samlSecurityTokenHandler, expectedException);

            expectedException = ExpectedException.ArgumentNullException( substringExpected: "Parameter name: validationParameters");
            ValidateIssuer("bob", null, samlSecurityTokenHandler, expectedException);

            expectedException = ExpectedException.SecurityTokenInvalidIssuerException(substringExpected: "IDX10204");
            ValidateIssuer("bob", new TokenValidationParameters { }, samlSecurityTokenHandler, expectedException);

            expectedException = ExpectedException.NoExceptionExpected;
            string issuer = ValidateIssuer("bob", new TokenValidationParameters { ValidIssuer = "bob" }, samlSecurityTokenHandler, expectedException);
            Assert.True(issuer == "bob", "issuer mismatch");

            expectedException = ExpectedException.SecurityTokenInvalidIssuerException(substringExpected: "IDX10205");
            ValidateIssuer("bob", new TokenValidationParameters { ValidIssuer = "frank" }, samlSecurityTokenHandler, expectedException);

            List<string> validIssuers = new List<string> { "john", "paul", "george", "ringo" };
            expectedException = ExpectedException.SecurityTokenInvalidIssuerException(substringExpected: "IDX10205");
            ValidateIssuer("bob", new TokenValidationParameters { ValidIssuers = validIssuers }, samlSecurityTokenHandler, expectedException);

            expectedException = ExpectedException.NoExceptionExpected;
            ValidateIssuer("bob", new TokenValidationParameters { ValidateIssuer = false }, samlSecurityTokenHandler, expectedException);

            validIssuers.Add("bob");
            expectedException = ExpectedException.NoExceptionExpected;
            issuer = ValidateIssuer("bob", new TokenValidationParameters { ValidIssuers = validIssuers }, samlSecurityTokenHandler, expectedException);
            Assert.True(issuer == "bob", "issuer mismatch");

            expectedException =  ExpectedException.SecurityTokenInvalidIssuerException(substringExpected: "IDX10204");
            TokenValidationParameters validationParameters = new TokenValidationParameters
            {
                ValidateAudience = false,
                IssuerValidator = IdentityUtilities.IssuerValidatorEcho,
            };

            ValidateIssuer("bob", validationParameters, samlSecurityTokenHandler, expectedException);
                        
            // no delegate secondary should still succeed
            expectedException = ExpectedException.NoExceptionExpected;
            validationParameters = new TokenValidationParameters
            {
                ValidateAudience = false,
                ValidIssuers = validIssuers,
            };

            issuer = ValidateIssuer("bob", validationParameters, samlSecurityTokenHandler, expectedException);
            Assert.True(issuer == "bob", "issuer mismatch");

            // no delegate, secondary should fail
            validIssuers = new List<string> { "john", "paul", "george", "ringo" };
            expectedException = ExpectedException.SecurityTokenInvalidIssuerException(substringExpected: "IDX10205");
            validationParameters = new TokenValidationParameters
            {
                IssuerSigningKey = new X509SecurityKey(KeyingMaterial.DefaultCert_2048),
                ValidateAudience = false,
                ValidIssuer = "http://Bob",
            };
            ValidateIssuer("bob", validationParameters, samlSecurityTokenHandler, expectedException);

            validationParameters.ValidateIssuer = false;
            validationParameters.IssuerValidator = IdentityUtilities.IssuerValidatorThrows;
            ValidateIssuer("bob", validationParameters, samlSecurityTokenHandler, ExpectedException.NoExceptionExpected);
        }

        private string ValidateIssuer(string issuer, TokenValidationParameters validationParameters, DerivedSamlSecurityTokenHandler samlSecurityTokenHandler, ExpectedException expectedException)
        {
            string returnVal = string.Empty;
            try
            {
                // TODO - need to pass actual Saml2Token
                returnVal = samlSecurityTokenHandler.ValidateIssuerPublic(issuer, null, validationParameters);
                expectedException.ProcessNoException();
            }
            catch (Exception exception)
            {
                expectedException.ProcessException(exception);
            }

            return returnVal;
        }

#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant
        [Theory, MemberData("ValidateTokenTheoryData")]
#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
        public void ValidateToken(CreateAndValidateParams theoryData)
        {
            TestUtilities.TestHeader("Saml2SecurityTokenHandlerTests.ValidateToken." + theoryData.TestId, ref _firstValidateToken);

            ClaimsPrincipal retVal = null;
            try
            {
                SecurityToken validatedToken;
                retVal = theoryData.SecurityTokenHandler.ValidateToken(theoryData.Token, theoryData.TokenValidationParameters, out validatedToken);
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
                        ExpectedException = ExpectedException.ArgumentNullException(substringExpected: "IDX10000: The parameter 'token'"),
                        SecurityTokenHandler = tokenHandler,
                        TestId = "Null-SecurityToken",
                        Token = null,
                        TokenValidationParameters = new TokenValidationParameters()
                    });

                theoryData.Add(
                    new CreateAndValidateParams
                    {
                        ExpectedException = ExpectedException.ArgumentNullException(substringExpected: "IDX10000: The parameter 'validationParameters'"),
                        SecurityTokenHandler = tokenHandler,
                        TestId = "NULL-TokenValidationParameters",
                        Token = "s",
                        TokenValidationParameters = null,
                    });

                tokenHandler = new Saml2SecurityTokenHandler();
                tokenHandler.MaximumTokenSizeInBytes = 1;
                theoryData.Add(
                    new CreateAndValidateParams
                    {
                        ExpectedException = ExpectedException.ArgumentException(substringExpected: "IDX10209:"),
                        SecurityTokenHandler = tokenHandler,
                        TestId = "SecurityTokenTooLarge",
                        Token = "ss",
                        TokenValidationParameters = new TokenValidationParameters(),
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

        private void ValidateAudience()
        {
            Saml2SecurityTokenHandler tokenHandler = new Saml2SecurityTokenHandler();
            ExpectedException expectedException;
            string samlString = "";//IdentityUtilities.CreateSaml2Token();

            TokenValidationParameters validationParameters =
                new TokenValidationParameters
                {
                    IssuerSigningKey = IdentityUtilities.DefaultAsymmetricSigningKey,
                    RequireExpirationTime = false,
                    RequireSignedTokens = false,
                    ValidIssuer = IdentityUtilities.DefaultIssuer,
                };

            // Do not validate audience
            validationParameters.ValidateAudience = false;
            expectedException = ExpectedException.NoExceptionExpected;
            TestUtilities.ValidateToken(securityToken: samlString, validationParameters: validationParameters, tokenValidator: tokenHandler, expectedException: expectedException);

            // no valid audiences
            validationParameters.ValidateAudience = true;
            expectedException = ExpectedException.SecurityTokenInvalidAudienceException("IDX10208");
            TestUtilities.ValidateToken(securityToken: samlString, validationParameters: validationParameters, tokenValidator: tokenHandler, expectedException: expectedException);

            validationParameters.ValidateAudience = true;
            validationParameters.ValidAudience = "John";
            expectedException = new ExpectedException(typeExpected: typeof(SecurityTokenInvalidAudienceException), substringExpected: "IDX10214");
            TestUtilities.ValidateToken(securityToken: samlString, validationParameters: validationParameters, tokenValidator: tokenHandler, expectedException: expectedException);

            // UriKind.Absolute, no match.
            validationParameters.ValidateAudience = true;
            validationParameters.ValidAudience = IdentityUtilities.NotDefaultAudience;
            expectedException = new ExpectedException(typeExpected: typeof(SecurityTokenInvalidAudienceException), substringExpected: "IDX10214");
            TestUtilities.ValidateToken(securityToken: samlString, validationParameters: validationParameters, tokenValidator: tokenHandler, expectedException: expectedException);

            expectedException = ExpectedException.NoExceptionExpected;
            validationParameters.ValidAudience = IdentityUtilities.DefaultAudience;
            validationParameters.ValidAudiences = null;
            TestUtilities.ValidateToken(securityToken: samlString, validationParameters: validationParameters, tokenValidator: tokenHandler, expectedException: expectedException);

            // !UriKind.Absolute
            List<string> audiences = new List<string> { "John", "Paul", "George", "Ringo" };
            validationParameters.ValidAudience = null;
            validationParameters.ValidAudiences = audiences;
            validationParameters.ValidateAudience = false;
            expectedException = ExpectedException.NoExceptionExpected;
            TestUtilities.ValidateToken(securityToken: samlString, validationParameters: validationParameters, tokenValidator: tokenHandler, expectedException: expectedException);

            // UriKind.Absolute, no match
            audiences = new List<string> { "http://www.John.com", "http://www.Paul.com", "http://www.George.com", "http://www.Ringo.com", "    " };
            validationParameters.ValidAudience = null;
            validationParameters.ValidAudiences = audiences;
            validationParameters.ValidateAudience = false;
            expectedException = ExpectedException.NoExceptionExpected;
            TestUtilities.ValidateToken(securityToken: samlString, validationParameters: validationParameters, tokenValidator: tokenHandler, expectedException: expectedException);

            validationParameters.ValidateAudience = true;
            expectedException = new ExpectedException(typeExpected: typeof(SecurityTokenInvalidAudienceException), substringExpected: "IDX10214");
            TestUtilities.ValidateToken(securityToken: samlString, validationParameters: validationParameters, tokenValidator: tokenHandler, expectedException: expectedException);

            validationParameters.ValidateAudience = true;
            expectedException = ExpectedException.NoExceptionExpected;
            audiences.Add(IdentityUtilities.DefaultAudience);
            TestUtilities.ValidateToken(securityToken: samlString, validationParameters: validationParameters, tokenValidator: tokenHandler, expectedException: expectedException);

            validationParameters.AudienceValidator =
                (aud, token, tvp) =>
                {
                    return false;
                };
            expectedException = new ExpectedException(typeExpected: typeof(SecurityTokenInvalidAudienceException), substringExpected: "IDX10231:");
            audiences.Add(IdentityUtilities.DefaultAudience);
            TestUtilities.ValidateToken(securityToken: samlString, validationParameters: validationParameters, tokenValidator: tokenHandler, expectedException: expectedException);

            validationParameters.ValidateAudience = false;
            validationParameters.AudienceValidator = IdentityUtilities.AudienceValidatorThrows;
            TestUtilities.ValidateToken(securityToken: samlString, validationParameters: validationParameters, tokenValidator: tokenHandler, expectedException: ExpectedException.NoExceptionExpected);
        }

        private class DerivedSamlSecurityTokenHandler : Saml2SecurityTokenHandler
        {
            public ClaimsIdentity CreateClaimsPublic(Saml2SecurityToken samlToken, string issuer, TokenValidationParameters validationParameters)
            {
                return base.CreateClaimsIdentity(samlToken, issuer, validationParameters);
            }

            public string ValidateIssuerPublic(string issuer, SecurityToken securityToken, TokenValidationParameters validationParameters)
            {
                return base.ValidateIssuer(issuer, securityToken, validationParameters);
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
