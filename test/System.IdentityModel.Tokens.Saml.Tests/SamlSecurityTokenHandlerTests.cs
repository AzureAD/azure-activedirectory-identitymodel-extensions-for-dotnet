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

using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Tokens.Tests;
using Xunit;

namespace System.IdentityModel.Tokens.Saml.Tests
{
    /// <summary>
    /// 
    /// </summary>
    public class SamlSecurityTokenHandlerTests
    {
        [Fact]
        public void Constructors()
        {
            SamlSecurityTokenHandler samlSecurityTokenHandler = new SamlSecurityTokenHandler();
        }

        [Fact]
        public void Defaults()
        {
            SamlSecurityTokenHandler samlSecurityTokenHandler = new SamlSecurityTokenHandler();
            Assert.True(samlSecurityTokenHandler.MaximumTokenSizeInBytes == TokenValidationParameters.DefaultMaximumTokenSizeInBytes, "MaximumTokenSizeInBytes");
        }

        [Fact]
        public void GetSets()
        {
            SamlSecurityTokenHandler samlSecurityTokenHandler = new SamlSecurityTokenHandler();
            TestUtilities.SetGet(samlSecurityTokenHandler, "MaximumTokenSizeInBytes", (object)0, ExpectedException.ArgumentOutOfRangeException(substringExpected: "IDX10101"));
            TestUtilities.SetGet(samlSecurityTokenHandler, "MaximumTokenSizeInBytes", (object)1, ExpectedException.NoExceptionExpected);
        }

        /*
        [Fact]
        public void Protected()
        {
            CreateClaims();
        }

        private void CreateClaims()
        {
            PublicSamlSecurityTokenHandler samlSecurityTokenHandler = new PublicSamlSecurityTokenHandler();
            ExpectedException expectedException = ExpectedException.ArgumentNullException(substringExpected: "samlToken");
            CreateClaims(null, "issuer", new TokenValidationParameters(), samlSecurityTokenHandler: samlSecurityTokenHandler, expectedException: expectedException);
        }

        private void CreateClaims(SamlSecurityToken samlToken, string issuer, TokenValidationParameters validationParameters, PublicSamlSecurityTokenHandler samlSecurityTokenHandler, ExpectedException expectedException)
        {
            try
            {
                samlSecurityTokenHandler.CreateClaimsPublic(samlToken, issuer, validationParameters );
                expectedException.ProcessNoException();
            }
            catch (Exception exception)
            {
                expectedException.ProcessException(exception);
            }
        }

        [Fact]
        public void Publics()
        {
            CanReadToken();
            ValidateIssuer();
            ValidateToken();
        }

        private void CanReadToken()
        {
            // CanReadToken
            SamlSecurityTokenHandler samlSecurityTokenHandler = new SamlSecurityTokenHandler();
            Assert.False(CanReadToken(securityToken: null, samlSecurityTokenHandler: samlSecurityTokenHandler, expectedException: ExpectedException.NoExceptionExpected));

            string samlString = new string('S', TokenValidationParameters.DefaultMaximumTokenSizeInBytes + 1);
            Assert.False(CanReadToken(securityToken: samlString, samlSecurityTokenHandler: samlSecurityTokenHandler, expectedException: ExpectedException.NoExceptionExpected));

            samlString = new string('S', TokenValidationParameters.DefaultMaximumTokenSizeInBytes);
            Assert.False(CanReadToken(securityToken: samlString, samlSecurityTokenHandler: samlSecurityTokenHandler, expectedException: ExpectedException.NoExceptionExpected));

            samlString = IdentityUtilities.CreateSamlToken();
            Assert.True(CanReadToken(securityToken: samlString, samlSecurityTokenHandler: samlSecurityTokenHandler, expectedException: ExpectedException.NoExceptionExpected));
        }
        private bool CanReadToken(string securityToken, SamlSecurityTokenHandler samlSecurityTokenHandler, ExpectedException expectedException)
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
            PublicSamlSecurityTokenHandler samlSecurityTokenHandler = new PublicSamlSecurityTokenHandler();
            SamlSecurityToken samlToken = IdentityUtilities.CreateSamlSecurityToken();

            ValidateIssuer(IdentityUtilities.DefaultIssuer, null, samlToken, samlSecurityTokenHandler, ExpectedException.ArgumentNullException(substringExpected: "name: validationParameters"));
            ValidateIssuer("bob", null, samlToken, samlSecurityTokenHandler, ExpectedException.ArgumentNullException(substringExpected: "name: validationParameters"));
            ValidateIssuer("bob", new TokenValidationParameters { ValidateIssuer = false }, samlToken, samlSecurityTokenHandler, ExpectedException.NoExceptionExpected);
            ValidateIssuer("bob", new TokenValidationParameters { }, samlToken, samlSecurityTokenHandler, ExpectedException.SecurityTokenInvalidIssuerException(substringExpected: "IDX10204"));
            ValidateIssuer(IdentityUtilities.DefaultIssuer, new TokenValidationParameters { ValidIssuer = IdentityUtilities.DefaultIssuer }, samlToken, samlSecurityTokenHandler, ExpectedException.NoExceptionExpected);
            ValidateIssuer("bob", new TokenValidationParameters { ValidIssuer = "frank" }, samlToken, samlSecurityTokenHandler, ExpectedException.SecurityTokenInvalidIssuerException(substringExpected: "IDX10205"));

            List<string> validIssuers = new List<string> { "john", "paul", "george", "ringo" };
            ValidateIssuer("bob", new TokenValidationParameters { ValidIssuers = validIssuers }, samlToken, samlSecurityTokenHandler, ExpectedException.SecurityTokenInvalidIssuerException(substringExpected: "IDX10205"));
            ValidateIssuer("bob", new TokenValidationParameters { ValidateIssuer = false }, samlToken, samlSecurityTokenHandler, ExpectedException.NoExceptionExpected);

            validIssuers.Add(IdentityUtilities.DefaultIssuer);
            string issuer = ValidateIssuer(IdentityUtilities.DefaultIssuer, new TokenValidationParameters { ValidIssuers = validIssuers }, samlToken, samlSecurityTokenHandler, ExpectedException.NoExceptionExpected);
            Assert.True(issuer == IdentityUtilities.DefaultIssuer, "issuer mismatch");

            TokenValidationParameters validationParameters = new TokenValidationParameters
            {
                ValidateAudience = false,
                IssuerValidator = IdentityUtilities.IssuerValidatorEcho,
            };

            ValidateIssuer("bob", validationParameters, samlToken, samlSecurityTokenHandler, ExpectedException.SecurityTokenInvalidIssuerException(substringExpected: "IDX10204"));

            validationParameters.ValidateIssuer = false;
            validationParameters.IssuerValidator = IdentityUtilities.IssuerValidatorThrows;
            ValidateIssuer("bob", validationParameters, samlToken, samlSecurityTokenHandler, ExpectedException.NoExceptionExpected);

        }

        private string ValidateIssuer(string issuer, TokenValidationParameters validationParameters, SamlSecurityToken samlToken, PublicSamlSecurityTokenHandler samlSecurityTokenHandler, ExpectedException expectedException)
        {
            string returnVal = string.Empty;
            try
            {
                returnVal = samlSecurityTokenHandler.ValidateIssuerPublic(issuer, samlToken, validationParameters);
                expectedException.ProcessNoException();
            }
            catch (Exception exception)
            {
                expectedException.ProcessException(exception);
            }

            return returnVal;
        }

        private void ValidateToken()
        {
            // parameter validation
            SamlSecurityTokenHandler tokenHandler = new SamlSecurityTokenHandler();
            ExpectedException expectedException = ExpectedException.ArgumentNullException(substringExpected: "name: securityToken");
            TestUtilities.ValidateToken(securityToken: null, validationParameters: new TokenValidationParameters(), tokenValidator: tokenHandler, expectedException: expectedException);

            expectedException = ExpectedException.ArgumentNullException(substringExpected: "name: validationParameters");
            TestUtilities.ValidateToken(securityToken: "s", validationParameters: null, tokenValidator: tokenHandler, expectedException: expectedException);

            expectedException = ExpectedException.ArgumentException(substringExpected: "IDX10209");
            tokenHandler.MaximumTokenSizeInBytes = 1;
            TestUtilities.ValidateToken(securityToken: "ss", validationParameters: new TokenValidationParameters(), tokenValidator: tokenHandler, expectedException: expectedException);

            tokenHandler.MaximumTokenSizeInBytes = TokenValidationParameters.DefaultMaximumTokenSizeInBytes;
            string samlToken = IdentityUtilities.CreateSamlToken();

            ValidateAudience();

            SecurityTokenDescriptor tokenDescriptor =
                new SecurityTokenDescriptor
                {
                    AppliesToAddress = IdentityUtilities.DefaultAudience,
                    Lifetime = new Lifetime(DateTime.UtcNow, DateTime.UtcNow + TimeSpan.FromHours(1)),
                    SigningCredentials = KeyingMaterial.DefaultAsymmetricSigningCreds_2048_RsaSha2_Sha2,
                    Subject = IdentityUtilities.DefaultClaimsIdentity,
                    TokenIssuerName = IdentityUtilities.DefaultIssuer,
                };

            samlToken = IdentityUtilities.CreateSamlToken(tokenDescriptor);
            TokenValidationParameters validationParameters =
                new TokenValidationParameters
                {
                    IssuerSigningToken = KeyingMaterial.DefaultAsymmetricX509Token_2048,
                    ValidAudience = IdentityUtilities.DefaultAudience,
                    ValidIssuer = IdentityUtilities.DefaultIssuer,
                };

            TestUtilities.ValidateTokenReplay(samlToken, tokenHandler, validationParameters);

            TestUtilities.ValidateToken(samlToken, validationParameters, tokenHandler, ExpectedException.NoExceptionExpected);
            validationParameters.LifetimeValidator =
                (nb, exp, st, tvp) =>
                {
                    return false;
                };
            TestUtilities.ValidateToken(samlToken, validationParameters, tokenHandler, new ExpectedException(typeExpected: typeof(SecurityTokenInvalidLifetimeException), substringExpected: "IDX10230:"));

            validationParameters.ValidateLifetime = false;
            validationParameters.LifetimeValidator = IdentityUtilities.LifetimeValidatorThrows;
            TestUtilities.ValidateToken(securityToken: samlToken, validationParameters: validationParameters, tokenValidator: tokenHandler, expectedException: ExpectedException.NoExceptionExpected);
        }

        private void ValidateAudience()
        {
            SamlSecurityTokenHandler tokenHandler = new SamlSecurityTokenHandler();
            ExpectedException expectedException;

            string samlString = IdentityUtilities.CreateSamlToken();

            TokenValidationParameters validationParameters =
                new TokenValidationParameters
                {
                    ValidIssuer = IdentityUtilities.DefaultIssuer,
                    IssuerSigningToken = IdentityUtilities.DefaultAsymmetricSigningToken,
                };

            // Do not validate audience
            validationParameters.ValidateAudience = false;
            expectedException = ExpectedException.NoExceptionExpected;
            TestUtilities.ValidateToken(securityToken: samlString, validationParameters: validationParameters, tokenValidator: tokenHandler, expectedException: ExpectedException.NoExceptionExpected);


            validationParameters.ValidateAudience = true;
            expectedException = ExpectedException.SecurityTokenInvalidAudienceException();
            TestUtilities.ValidateToken(securityToken: samlString, validationParameters: validationParameters, tokenValidator: tokenHandler, expectedException: expectedException);

            validationParameters.ValidateAudience = true;
            validationParameters.ValidAudience = "John";
            expectedException = ExpectedException.SecurityTokenInvalidAudienceException(substringExpected: "IDX10214:");
            TestUtilities.ValidateToken(securityToken: samlString, validationParameters: validationParameters, tokenValidator: tokenHandler, expectedException: expectedException);

            // UriKind.Absolute, no match.
            validationParameters.ValidateAudience = true;
            validationParameters.ValidAudience = IdentityUtilities.NotDefaultAudience;
            expectedException = ExpectedException.SecurityTokenInvalidAudienceException(substringExpected: "IDX10214:");
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
            expectedException = ExpectedException.SecurityTokenInvalidAudienceException(substringExpected: "IDX10214");
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
            TestUtilities.ValidateToken(securityToken: samlString, validationParameters: validationParameters, tokenValidator: tokenHandler, expectedException: expectedException);

            validationParameters.ValidateAudience = false;
            validationParameters.AudienceValidator = IdentityUtilities.AudienceValidatorThrows;
            TestUtilities.ValidateToken(securityToken: samlString, validationParameters: validationParameters, tokenValidator: tokenHandler, expectedException: ExpectedException.NoExceptionExpected);
        }

        private class PublicSamlSecurityTokenHandler : SamlSecurityTokenHandler
        {
            public ClaimsIdentity CreateClaimsPublic(SamlSecurityToken samlToken, string issuer, TokenValidationParameters validationParameters)
            {
                return base.CreateClaimsIdentity(samlToken, issuer, validationParameters);
            }

            public string ValidateIssuerPublic(string issuer, SamlSecurityToken samlToken, TokenValidationParameters validationParameters)
            {
                return base.ValidateIssuer(issuer, samlToken, validationParameters);
            }
        } */
    }
}
