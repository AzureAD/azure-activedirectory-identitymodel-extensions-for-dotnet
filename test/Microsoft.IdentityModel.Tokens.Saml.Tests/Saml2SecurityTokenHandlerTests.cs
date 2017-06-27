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
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.IdentityModel.Tokens.Saml2;
using Microsoft.IdentityModel.Tests;
using Xunit;
using Microsoft.IdentityModel.Xml;

namespace Microsoft.IdentityModel.Tokens.Saml.Tests
{
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
            TestUtilities.SetGet(samlSecurityTokenHandler, "MaximumTokenSizeInBytes", (object)0, ExpectedException.ArgumentOutOfRangeException("IDX10101:"));
            TestUtilities.SetGet(samlSecurityTokenHandler, "MaximumTokenSizeInBytes", (object)1, ExpectedException.NoExceptionExpected);
        }

#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant
        [Theory, MemberData("CanReadTokenTheoryData")]
#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
        public void CanReadToken(SamlTheoryData theoryData)
        {
            TestUtilities.WriteHeader($"{this}.CanReadToken", theoryData);
            try
            {
                // TODO - need to pass actual Saml2Token

                if (theoryData.CanRead != theoryData.Handler.CanReadToken(theoryData.Token))
                    Assert.False(true, $"Expected CanRead != CanRead, token: {theoryData.Token}");

                theoryData.ExpectedException.ProcessNoException();
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex);
            }
        }

        public static TheoryData<SamlTheoryData> CanReadTokenTheoryData
        {
            get
            {
                var theoryData = new TheoryData<SamlTheoryData>();
                
                // CanReadToken
                var handler = new Saml2SecurityTokenHandler();
                theoryData.Add(
                    new SamlTheoryData
                    {
                        CanRead = false,
                        First = true,
                        Handler = handler,
                        TestId = "Null Token",
                        Token = null
                    });

                theoryData.Add(
                    new SamlTheoryData
                    {
                        CanRead = false,
                        Handler = handler,
                        TestId = "DefaultMaximumTokenSizeInBytes + 1",
                        Token = new string('S', TokenValidationParameters.DefaultMaximumTokenSizeInBytes + 2)
                    });

                theoryData.Add(
                    new SamlTheoryData
                    {
                        CanRead = true,
                        Handler = handler,
                        TestId = nameof(RefrenceTokens.Saml2Token_Valid),
                        Token = RefrenceTokens.Saml2Token_Valid
                    });

                return theoryData;
            }
        }

#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant
        [Theory, MemberData("ReadTokenTheoryData")]
#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
        public void ReadToken(SamlTheoryData theoryData)
        {
            TestUtilities.WriteHeader($"{this}.ReadToken", theoryData);
            try
            {
                theoryData.Handler.ReadToken(theoryData.Token);
                theoryData.ExpectedException.ProcessNoException();
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex);
            }
        }

        public static TheoryData<SamlTheoryData> ReadTokenTheoryData
        {
            get
            {
                var theoryData = new TheoryData<SamlTheoryData>();

                theoryData.Add(new SamlTheoryData
                {
                    ExpectedException = ExpectedException.NoExceptionExpected,
                    First = true,
                    Handler = new Saml2SecurityTokenHandler(),
                    TestId = nameof(RefrenceTokens.Saml2Token_Valid),
                    Token = RefrenceTokens.Saml2Token_Valid
                });

                return theoryData;
            }
        }

#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant
        [Theory, MemberData("ValidateAudienceTheoryData")]
#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
        public void ValidateAudience(SamlTheoryData theoryData)
        {
            TestUtilities.WriteHeader($"{this}.ValidateAudience", theoryData);
            try
            {
                // TODO - need to pass actual Saml2Token
                ((theoryData.Handler)as Saml2SecurityTokenHandlerPublic).ValidateAudiencePublic(theoryData.Audiences, null, theoryData.ValidationParameters);
                theoryData.ExpectedException.ProcessNoException();
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex);
            }
        }

        public static TheoryData<SamlTheoryData> ValidateAudienceTheoryData
        {
            get
            {
                var theoryData = new TheoryData<SamlTheoryData>();
                var handler = new Saml2SecurityTokenHandlerPublic();

                ValidateTheoryData.AddValidateAudienceTheoryData(theoryData, handler);

                return theoryData;
            }
        }

#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant
        [Theory, MemberData("ValidateIssuerTheoryData")]
#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
        public void ValidateIssuer(SamlTheoryData theoryData)
        {
            TestUtilities.WriteHeader($"{this}.ValidateIssuer", theoryData);
            try
            {
                // TODO - need to pass actual Saml2Token
                ((theoryData.Handler)as Saml2SecurityTokenHandlerPublic).ValidateIssuerPublic(theoryData.Issuer, null, theoryData.ValidationParameters);
                theoryData.ExpectedException.ProcessNoException();
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex);
            }
        }

        public static TheoryData<SamlTheoryData> ValidateIssuerTheoryData
        {
            get
            {
                var theoryData = new TheoryData<SamlTheoryData>();
                var handler = new Saml2SecurityTokenHandlerPublic();

                ValidateTheoryData.AddValidateIssuerTheoryData(theoryData, handler);

                return theoryData;
            }
        }

#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant
        [Theory, MemberData("ValidateTokenTheoryData")]
#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
        public void ValidateToken(SamlTheoryData theoryData)
        {
            TestUtilities.WriteHeader($"{this}.ValidateToken", theoryData);

            ClaimsPrincipal retVal = null;
            try
            {
                retVal = (theoryData.Handler as Saml2SecurityTokenHandler).ValidateToken(theoryData.Token, theoryData.ValidationParameters, out SecurityToken validatedToken);
                theoryData.ExpectedException.ProcessNoException();
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex);
            }
        }

        /// <summary>
        /// Canoncalizing reader is not yet supported in .net core
        /// </summary>
        public static TheoryData<SamlTheoryData> ValidateTokenTheoryData
        {
            get
            {
                // uncomment to view exception displayed to user
                // ExpectedException.DefaultVerbose = true;

                var theoryData = new TheoryData<SamlTheoryData>();

                theoryData.Add(
                    new SamlTheoryData
                    {
                        ExpectedException = ExpectedException.ArgumentNullException("IDX10000:"),
                        First = true,
                        Handler = new Saml2SecurityTokenHandler(),
                        TestId = "Null-SecurityToken",
                        Token = null,
                        ValidationParameters = new TokenValidationParameters()
                    });

                theoryData.Add(
                    new SamlTheoryData
                    {
                        ExpectedException = ExpectedException.ArgumentNullException("IDX10000:"),
                        Handler = new Saml2SecurityTokenHandler(),
                        TestId = "NULL-TokenValidationParameters",
                        Token = "s",
                        ValidationParameters = null,
                    });

                var tokenHandler = new Saml2SecurityTokenHandler();
                tokenHandler.MaximumTokenSizeInBytes = 1;
                theoryData.Add(
                    new SamlTheoryData
                    {
                        ExpectedException = ExpectedException.ArgumentException("IDX10209:"),
                        Handler = tokenHandler,
                        TestId = "SecurityTokenTooLarge",
                        Token = "ss",
                        ValidationParameters = new TokenValidationParameters(),
                    });

                theoryData.Add(
                    new SamlTheoryData
                    {
                        ExpectedException = new ExpectedException(typeof(Saml2SecurityTokenReadException), "IDX11106:"),
                        Handler = new Saml2SecurityTokenHandler(),
                        TestId = nameof(RefrenceTokens.Saml2Token_MissingVersion),
                        Token = RefrenceTokens.Saml2Token_MissingVersion,
                        ValidationParameters = new TokenValidationParameters(),
                    });

                theoryData.Add(
                    new SamlTheoryData
                    {
                        ExpectedException = new ExpectedException(typeof(Saml2SecurityTokenReadException), "IDX11137:"),
                        Handler = new Saml2SecurityTokenHandler(),
                        TestId = nameof(RefrenceTokens.Saml2Token_VersionNotV20),
                        Token = RefrenceTokens.Saml2Token_VersionNotV20,
                        ValidationParameters = new TokenValidationParameters(),
                    });

                theoryData.Add(
                    new SamlTheoryData
                    {
                        ExpectedException = new ExpectedException(typeof(Saml2SecurityTokenReadException), "IDX11106:"),
                        Handler = new Saml2SecurityTokenHandler(),
                        TestId = nameof(RefrenceTokens.Saml2Token_IdMissing),
                        Token = RefrenceTokens.Saml2Token_IdMissing,
                        ValidationParameters = new TokenValidationParameters(),
                    });

                theoryData.Add(
                    new SamlTheoryData
                    {
                        ExpectedException = new ExpectedException(typeof(Saml2SecurityTokenReadException), "IDX11106:"),
                        Handler = new Saml2SecurityTokenHandler(),
                        TestId = nameof(RefrenceTokens.Saml2Token_IssuerInstantMissing),
                        Token = RefrenceTokens.Saml2Token_IssuerInstantMissing,
                        ValidationParameters = new TokenValidationParameters(),
                    });

                theoryData.Add(
                    new SamlTheoryData
                    {
                        ExpectedException = new ExpectedException(typeof(Saml2SecurityTokenReadException), "IDX11102:", typeof(FormatException)),
                        Handler = new Saml2SecurityTokenHandler(),
                        TestId = nameof(RefrenceTokens.Saml2Token_IssuerInstantFormatError),
                        Token = RefrenceTokens.Saml2Token_IssuerInstantFormatError,
                        ValidationParameters = new TokenValidationParameters(),
                    });

                theoryData.Add(
                    new SamlTheoryData
                    {
                        ExpectedException = new ExpectedException(typeof(Saml2SecurityTokenReadException), "IDX11102:", typeof(XmlReadException)),
                        Handler = tokenHandler = new Saml2SecurityTokenHandler(),
                        TestId = nameof(RefrenceTokens.Saml2Token_IssuerMissing),
                        Token = RefrenceTokens.Saml2Token_IssuerMissing,
                        ValidationParameters = new TokenValidationParameters(),
                    });

                theoryData.Add(
                    new SamlTheoryData
                    {
                        ExpectedException = new ExpectedException(typeof(Saml2SecurityTokenReadException), "IDX11108:"),
                        Handler = new Saml2SecurityTokenHandler(),
                        TestId = nameof(RefrenceTokens.Saml2Token_NoSubjectNoStatements),
                        Token = RefrenceTokens.Saml2Token_NoSubjectNoStatements,
                        ValidationParameters = new TokenValidationParameters(),
                    });

                theoryData.Add(
                    new SamlTheoryData
                    {
                        ExpectedException = new ExpectedException(typeof(Saml2SecurityTokenReadException), "IDX11138:"),
                        Handler = new Saml2SecurityTokenHandler(),
                        TestId = nameof(RefrenceTokens.Saml2Token_NoAttributes),
                        Token = RefrenceTokens.Saml2Token_NoAttributes,
                        ValidationParameters = new TokenValidationParameters(),
                    });

                var keySet = new JsonWebKeySet(RefrenceTokens.AADJWKS);
                var certData = "MIIDBTCCAe2gAwIBAgIQY4RNIR0dX6dBZggnkhCRoDANBgkqhkiG9w0BAQsFADAtMSswKQYDVQQDEyJhY2NvdW50cy5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MB4XDTE3MDIxMzAwMDAwMFoXDTE5MDIxNDAwMDAwMFowLTErMCkGA1UEAxMiYWNjb3VudHMuYWNjZXNzY29udHJvbC53aW5kb3dzLm5ldDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMBEizU1OJms31S/ry7iav/IICYVtQ2MRPhHhYknHImtU03sgVk1Xxub4GD7R15i9UWIGbzYSGKaUtGU9lP55wrfLpDjQjEgaXi4fE6mcZBwa9qc22is23B6R67KMcVyxyDWei+IP3sKmCcMX7Ibsg+ubZUpvKGxXZ27YgqFTPqCT2znD7K81YKfy+SVg3uW6epW114yZzClTQlarptYuE2mujxjZtx7ZUlwc9AhVi8CeiLwGO1wzTmpd/uctpner6oc335rvdJikNmc1cFKCK+2irew1bgUJHuN+LJA0y5iVXKvojiKZ2Ii7QKXn19Ssg1FoJ3x2NWA06wc0CnruLsCAwEAAaMhMB8wHQYDVR0OBBYEFDAr/HCMaGqmcDJa5oualVdWAEBEMA0GCSqGSIb3DQEBCwUAA4IBAQAiUke5mA86R/X4visjceUlv5jVzCn/SIq6Gm9/wCqtSxYvifRXxwNpQTOyvHhrY/IJLRUp2g9/fDELYd65t9Dp+N8SznhfB6/Cl7P7FRo99rIlj/q7JXa8UB/vLJPDlr+NREvAkMwUs1sDhL3kSuNBoxrbLC5Jo4es+juQLXd9HcRraE4U3UZVhUS2xqjFOfaGsCbJEqqkjihssruofaxdKT1CPzPMANfREFJznNzkpJt4H0aMDgVzq69NxZ7t1JiIuc43xRjeiixQMRGMi1mAB75fTyfFJ/rWQ5J/9kh0HMZVtHsqICBF1tHMTMIK5rwoweY0cuCIpN7A/zMOQtoD";
                var aadCert = new X509Certificate2(Convert.FromBase64String(certData));
                theoryData.Add(
                    new SamlTheoryData
                    {
                        ExpectedException = ExpectedException.NoExceptionExpected,
                        Handler = new Saml2SecurityTokenHandler(),
                        TestId = $"{nameof(RefrenceTokens.Saml2Token_Valid)} IssuerSigningKey set",
                        Token = RefrenceTokens.Saml2Token_Valid,
                        ValidationParameters = new TokenValidationParameters
                        {
                            IssuerSigningKey = new X509SecurityKey(aadCert),
                            IssuerSigningKeys = keySet.GetSigningKeys(),
                            ValidateIssuer = false,
                            ValidateAudience = false,
                            ValidateLifetime = false,
                        }
                    });

                theoryData.Add(
                    new SamlTheoryData
                    {
                        ExpectedException = ExpectedException.NoExceptionExpected,
                        Handler = new Saml2SecurityTokenHandler(),
                        TestId = nameof(RefrenceTokens.Saml2Token_Valid_Spaces_Added),
                        Token = RefrenceTokens.Saml2Token_Valid_Spaces_Added,
                        ValidationParameters = new TokenValidationParameters
                        {
                            IssuerSigningKey = new X509SecurityKey(aadCert),
                            IssuerSigningKeys = keySet.GetSigningKeys(),
                            ValidateIssuer = false,
                            ValidateAudience = false,
                            ValidateLifetime = false,
                        }
                    });


                theoryData.Add(
                    new SamlTheoryData
                    {
                        ExpectedException = ExpectedException.SecurityTokenInvalidSignatureException("IDX10503:"),
                        Handler = new Saml2SecurityTokenHandler(),
                        TestId = nameof(RefrenceTokens.Saml2Token_Formated),
                        Token = RefrenceTokens.Saml2Token_Formated,
                        ValidationParameters = new TokenValidationParameters
                        {
                            IssuerSigningKey = new X509SecurityKey(aadCert),
                            IssuerSigningKeys = keySet.GetSigningKeys(),
                            ValidateIssuer = false,
                            ValidateAudience = false,
                            ValidateLifetime = false,
                        }
                    });

                theoryData.Add(
                    new SamlTheoryData
                    {
                        ExpectedException = ExpectedException.SecurityTokenInvalidSignatureException("IDX10503:"),
                        Handler = new Saml2SecurityTokenHandler(),
                        TestId = nameof(RefrenceTokens.Saml2Token_AttributeTampered),
                        Token = RefrenceTokens.Saml2Token_AttributeTampered,
                        ValidationParameters = new TokenValidationParameters
                        {
                            IssuerSigningKey = new X509SecurityKey(aadCert),
                            IssuerSigningKeys = keySet.GetSigningKeys(),
                            ValidateIssuer = false,
                            ValidateAudience = false,
                            ValidateLifetime = false,
                        }
                    });

                theoryData.Add(
                    new SamlTheoryData
                    {
                        ExpectedException = ExpectedException.SecurityTokenInvalidSignatureException("IDX10503:"),
                        Handler = new Saml2SecurityTokenHandler(),
                        TestId = nameof(RefrenceTokens.Saml2Token_DigestTampered),
                        Token = RefrenceTokens.Saml2Token_DigestTampered,
                        ValidationParameters = new TokenValidationParameters
                        {
                            IssuerSigningKey = new X509SecurityKey(aadCert),
                            IssuerSigningKeys = keySet.GetSigningKeys(),
                            ValidateIssuer = false,
                            ValidateAudience = false,
                            ValidateLifetime = false,
                        }
                    });

                theoryData.Add(
                    new SamlTheoryData
                    {
                        ExpectedException = ExpectedException.SecurityTokenSignatureKeyNotFoundException("IDX10501:"),
                        Handler = new Saml2SecurityTokenHandler(),
                        TestId = nameof(RefrenceTokens.Saml2Token_AttributeTampered_NoKeyMatch),
                        Token = RefrenceTokens.Saml2Token_AttributeTampered_NoKeyMatch,
                        ValidationParameters = new TokenValidationParameters
                        {
                            IssuerSigningKey = new X509SecurityKey(aadCert),
                            IssuerSigningKeys = keySet.GetSigningKeys(),
                            ValidateIssuer = false,
                            ValidateAudience = false,
                            ValidateLifetime = false,
                        }
                    });


                theoryData.Add(
                    new SamlTheoryData
                    {
                        ExpectedException = ExpectedException.SecurityTokenInvalidSignatureException("IDX10503:"),
                        Handler = new Saml2SecurityTokenHandler(),
                        TestId = nameof(RefrenceTokens.Saml2Token_SignatureTampered),
                        Token = RefrenceTokens.Saml2Token_SignatureTampered,
                        ValidationParameters = new TokenValidationParameters
                        {
                            IssuerSigningKey = new X509SecurityKey(aadCert),
                            IssuerSigningKeys = keySet.GetSigningKeys(),
                            ValidateIssuer = false,
                            ValidateAudience = false,
                            ValidateLifetime = false,
                        }
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

        private class Saml2SecurityTokenHandlerPublic : Saml2SecurityTokenHandler
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

        private class Saml2SecurityTokenPublic : Saml2SecurityToken
        {
            public Saml2SecurityTokenPublic(Saml2Assertion assertion)
                : base(assertion)
            { }
        }
    }
}
