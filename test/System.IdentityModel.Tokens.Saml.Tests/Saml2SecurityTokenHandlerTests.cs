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
using Xunit;

namespace System.IdentityModel.Tokens.Saml2.Tests
{
    /// <summary>
    /// 
    /// </summary>
    public class Saml2SecurityTokenHandlerTests
    {
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

        [Fact]
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

            samlString = IdentityUtilities.CreateSamlToken();
            Assert.False(CanReadToken(securityToken: samlString, samlSecurityTokenHandler: samlSecurityTokenHandler, expectedException: ExpectedException.NoExceptionExpected));

            samlString = IdentityUtilities.CreateSaml2Token();
            Assert.True(CanReadToken(securityToken: samlString, samlSecurityTokenHandler: samlSecurityTokenHandler, expectedException: ExpectedException.NoExceptionExpected));
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
            Assert.IsTrue(issuer == "bob", "issuer mismatch");

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
            Assert.IsTrue(issuer == "bob", "issuer mismatch");

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
            Assert.IsTrue(issuer == "bob", "issuer mismatch");

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
                returnVal = samlSecurityTokenHandler.ValidateIssuerPublic(issuer, new DerivedSaml2SecurityToken(), validationParameters);
                expectedException.ProcessNoException();
            }
            catch (Exception exception)
            {
                expectedException.ProcessException(exception);
            }

            return returnVal;
        }

        [Fact]
        public void ValidateToken()
        {
            // parameter validation
            Saml2SecurityTokenHandler tokenHandler = new Saml2SecurityTokenHandler();

            TestUtilities.ValidateToken(securityToken: null, validationParameters: new TokenValidationParameters(), tokenValidator: tokenHandler, expectedException: ExpectedException.ArgumentNullException(substringExpected: "name: securityToken"));
            TestUtilities.ValidateToken(securityToken: "s", validationParameters: null, tokenValidator: tokenHandler, expectedException: ExpectedException.ArgumentNullException(substringExpected: "name: validationParameters"));

            tokenHandler.MaximumTokenSizeInBytes = 1;
            TestUtilities.ValidateToken(securityToken: "ss", validationParameters: new TokenValidationParameters(), tokenValidator: tokenHandler, expectedException: ExpectedException.ArgumentException(substringExpected: "IDX10209"));

            tokenHandler.MaximumTokenSizeInBytes = TokenValidationParameters.DefaultMaximumTokenSizeInBytes;
            string samlToken = IdentityUtilities.CreateSaml2Token();
            TestUtilities.ValidateToken(samlToken, IdentityUtilities.DefaultAsymmetricTokenValidationParameters, tokenHandler, ExpectedException.NoExceptionExpected);

            // EncryptedAssertion
            SecurityTokenDescriptor tokenDescriptor =
                new SecurityTokenDescriptor
                {
                    AppliesToAddress = IdentityUtilities.DefaultAudience,
                    EncryptingCredentials = new EncryptedKeyEncryptingCredentials(KeyingMaterial.DefaultAsymmetricCert_2048),
                    Lifetime = new Lifetime(DateTime.UtcNow, DateTime.UtcNow + TimeSpan.FromHours(1)),
                    SigningCredentials = KeyingMaterial.DefaultAsymmetricSigningCreds_2048_RsaSha2_Sha2,
                    Subject = IdentityUtilities.DefaultClaimsIdentity,
                    TokenIssuerName = IdentityUtilities.DefaultIssuer,
                };

            samlToken = IdentityUtilities.CreateSaml2Token(tokenDescriptor);
            TestUtilities.ValidateToken(samlToken, IdentityUtilities.DefaultAsymmetricTokenValidationParameters, tokenHandler, new ExpectedException(typeExpected: typeof(EncryptedTokenDecryptionFailedException), substringExpected: "ID4022"));

            TokenValidationParameters validationParameters = IdentityUtilities.DefaultAsymmetricTokenValidationParameters;
            validationParameters.TokenDecryptionKeys = new List<SecurityKey>{ KeyingMaterial.DefaultX509Key_2048 }.AsReadOnly();
            TestUtilities.ValidateToken(samlToken, validationParameters, tokenHandler, ExpectedException.NoExceptionExpected);

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
            Saml2SecurityTokenHandler tokenHandler = new Saml2SecurityTokenHandler();
            ExpectedException expectedException;
            string samlString = IdentityUtilities.CreateSaml2Token();

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
            public DerivedSaml2SecurityToken()
            { }
        }
    }
}
