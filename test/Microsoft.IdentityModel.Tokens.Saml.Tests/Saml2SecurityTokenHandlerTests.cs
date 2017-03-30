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
using System.Security.Cryptography.X509Certificates;
using Microsoft.IdentityModel.Tokens.Saml2;
using Microsoft.IdentityModel.Tokens.Tests;
using Xunit;

namespace Microsoft.IdentityModel.Tokens.Saml.Tests
{
    public class Saml2SecurityTokenHandlerTests
    {
        private static bool _firstCanReadToken = true;
        private static bool _firstReadToken = true;
        private static bool _firstValidateAudience = true;
        private static bool _firstValidateIssuer = true;
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
            TestUtilities.SetGet(samlSecurityTokenHandler, "MaximumTokenSizeInBytes", (object)0, ExpectedException.ArgumentOutOfRangeException("IDX11010:"));
            TestUtilities.SetGet(samlSecurityTokenHandler, "MaximumTokenSizeInBytes", (object)1, ExpectedException.NoExceptionExpected);
        }

#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant
        [Theory, MemberData("CanReadTokenTheoryData")]
#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
        public void CanReadToken(CreateAndValidateParams theoryData)
        {
            TestUtilities.TestHeader("Saml2SecurityTokenHandlerTests.CanReadToken", theoryData.TestId, ref _firstCanReadToken);
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
                        ExpectedException = ExpectedException.ArgumentNullException("IDX10000:"),
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
                        Token = RefrenceTokens.Saml2Token_1
                    });

                theoryData.Add(
                    new CreateAndValidateParams
                    {
                        CanRead = false,
                        Handler = handler,
                        TestId = "Saml1Token_1",
                        Token = RefrenceTokens.Saml1Token_1
                    });

                return theoryData;
            }
        }
#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant
        [Theory, MemberData("ReadTokenTheoryData")]
#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
        public void ReadToken(CreateAndValidateParams theoryData)
        {
            TestUtilities.TestHeader("Saml2SecurityTokenHandlerTests.ReadToken", theoryData.TestId, ref _firstReadToken);
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

        public static TheoryData<CreateAndValidateParams> ReadTokenTheoryData
        {
            get
            {
                var theoryData = new TheoryData<CreateAndValidateParams>();

                theoryData.Add(
                    new CreateAndValidateParams
                    {
                        Handler = new Saml2SecurityTokenHandler(),
                        TestId = "AADSaml2Token",
                        Token = RefrenceTokens.Saml2Token_1
                    });

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
                ((theoryData.Handler)as DerivedSaml2SecurityTokenHandler).ValidateAudiencePublic(theoryData.Audiences, null, theoryData.ValidationParameters);
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
                var handler = new DerivedSaml2SecurityTokenHandler();

                ValidateTheoryData.AddValidateAudienceTheoryData(theoryData, handler);

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
                ((theoryData.Handler)as DerivedSaml2SecurityTokenHandler).ValidateIssuerPublic(theoryData.Issuer, null, theoryData.ValidationParameters);
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
                var handler = new DerivedSaml2SecurityTokenHandler();

                ValidateTheoryData.AddValidateIssuerTheoryData(theoryData, handler);

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
                retVal = (theoryData.Handler as Saml2SecurityTokenHandler).ValidateToken(theoryData.Token, theoryData.ValidationParameters, out validatedToken);
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

                tokenHandler = new Saml2SecurityTokenHandler();
                theoryData.Add(
                    new CreateAndValidateParams
                    {
                        ExpectedException = new ExpectedException(typeof(Saml2SecurityTokenReadException), "IDX11106:"),
                        Handler = tokenHandler,
                        TestId = "Saml2Token_MissingVersion",
                        Token = RefrenceTokens.Saml2Token_MissingVersion,
                        ValidationParameters = new TokenValidationParameters(),
                    });

                tokenHandler = new Saml2SecurityTokenHandler();
                theoryData.Add(
                    new CreateAndValidateParams
                    {
                        ExpectedException = new ExpectedException(typeof(Saml2SecurityTokenReadException), "IDX11137:"),
                        Handler = tokenHandler,
                        TestId = nameof(RefrenceTokens.Saml2Token_VersionNotV20),
                        Token = RefrenceTokens.Saml2Token_VersionNotV20,
                        ValidationParameters = new TokenValidationParameters(),
                    });

                tokenHandler = new Saml2SecurityTokenHandler();
                theoryData.Add(
                    new CreateAndValidateParams
                    {
                        ExpectedException = new ExpectedException(typeof(Saml2SecurityTokenReadException), "IDX11106:"),
                        Handler = tokenHandler,
                        TestId = nameof(RefrenceTokens.Saml2Token_IdMissing),
                        Token = RefrenceTokens.Saml2Token_IdMissing,
                        ValidationParameters = new TokenValidationParameters(),
                    });

                tokenHandler = new Saml2SecurityTokenHandler();
                theoryData.Add(
                    new CreateAndValidateParams
                    {
                        ExpectedException = new ExpectedException(typeof(Saml2SecurityTokenReadException), "IDX11106:"),
                        Handler = tokenHandler,
                        TestId = nameof(RefrenceTokens.Saml2Token_IssuerInstantMissing),
                        Token = RefrenceTokens.Saml2Token_IssuerInstantMissing,
                        ValidationParameters = new TokenValidationParameters(),
                    });


                tokenHandler = new Saml2SecurityTokenHandler();
                theoryData.Add(
                    new CreateAndValidateParams
                    {
                        ExpectedException = new ExpectedException(typeof(Saml2SecurityTokenReadException), "IDX11102:", typeof(FormatException)),
                        Handler = tokenHandler,
                        TestId = nameof(RefrenceTokens.Saml2Token_IssuerInstantFormatError),
                        Token = RefrenceTokens.Saml2Token_IssuerInstantFormatError,
                        ValidationParameters = new TokenValidationParameters(),
                    });


                tokenHandler = new Saml2SecurityTokenHandler();
                theoryData.Add(
                    new CreateAndValidateParams
                    {
                        ExpectedException = new ExpectedException(typeof(Saml2SecurityTokenReadException), "IDX11105:"),
                        Handler = tokenHandler,
                        TestId = nameof(RefrenceTokens.Saml2Token_IssuerMissing),
                        Token = RefrenceTokens.Saml2Token_IssuerMissing,
                        ValidationParameters = new TokenValidationParameters(),
                    });

                tokenHandler = new Saml2SecurityTokenHandler();
                theoryData.Add(
                    new CreateAndValidateParams
                    {
                        ExpectedException = new ExpectedException(typeof(Saml2SecurityTokenReadException), "IDX11108:"),
                        Handler = tokenHandler,
                        TestId = nameof(RefrenceTokens.Saml2Token_NoSubjectNoStatements),
                        Token = RefrenceTokens.Saml2Token_NoSubjectNoStatements,
                        ValidationParameters = new TokenValidationParameters(),
                    });

                var keySet = new JsonWebKeySet(RefrenceTokens.AADJWKS);
                var certData = "MIIDBTCCAe2gAwIBAgIQY4RNIR0dX6dBZggnkhCRoDANBgkqhkiG9w0BAQsFADAtMSswKQYDVQQDEyJhY2NvdW50cy5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MB4XDTE3MDIxMzAwMDAwMFoXDTE5MDIxNDAwMDAwMFowLTErMCkGA1UEAxMiYWNjb3VudHMuYWNjZXNzY29udHJvbC53aW5kb3dzLm5ldDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMBEizU1OJms31S/ry7iav/IICYVtQ2MRPhHhYknHImtU03sgVk1Xxub4GD7R15i9UWIGbzYSGKaUtGU9lP55wrfLpDjQjEgaXi4fE6mcZBwa9qc22is23B6R67KMcVyxyDWei+IP3sKmCcMX7Ibsg+ubZUpvKGxXZ27YgqFTPqCT2znD7K81YKfy+SVg3uW6epW114yZzClTQlarptYuE2mujxjZtx7ZUlwc9AhVi8CeiLwGO1wzTmpd/uctpner6oc335rvdJikNmc1cFKCK+2irew1bgUJHuN+LJA0y5iVXKvojiKZ2Ii7QKXn19Ssg1FoJ3x2NWA06wc0CnruLsCAwEAAaMhMB8wHQYDVR0OBBYEFDAr/HCMaGqmcDJa5oualVdWAEBEMA0GCSqGSIb3DQEBCwUAA4IBAQAiUke5mA86R/X4visjceUlv5jVzCn/SIq6Gm9/wCqtSxYvifRXxwNpQTOyvHhrY/IJLRUp2g9/fDELYd65t9Dp+N8SznhfB6/Cl7P7FRo99rIlj/q7JXa8UB/vLJPDlr+NREvAkMwUs1sDhL3kSuNBoxrbLC5Jo4es+juQLXd9HcRraE4U3UZVhUS2xqjFOfaGsCbJEqqkjihssruofaxdKT1CPzPMANfREFJznNzkpJt4H0aMDgVzq69NxZ7t1JiIuc43xRjeiixQMRGMi1mAB75fTyfFJ/rWQ5J/9kh0HMZVtHsqICBF1tHMTMIK5rwoweY0cuCIpN7A/zMOQtoD";
                var aadCert = new X509Certificate2(Convert.FromBase64String(certData));
                theoryData.Add(
                    new CreateAndValidateParams
                    {
                        Handler = new Saml2SecurityTokenHandler(),
                        TestId = nameof(RefrenceTokens.Saml2Token_1),
                        Token = RefrenceTokens.Saml2Token_1,
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
                    new CreateAndValidateParams
                    {
                        ExpectedException = ExpectedException.CryptographicException(),
                        Handler = new Saml2SecurityTokenHandler(),
                        TestId = "Saml2Token_AttributeTampered",
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
                    new CreateAndValidateParams
                    {
                        ExpectedException = ExpectedException.CryptographicException(),
                        Handler = new Saml2SecurityTokenHandler(),
                        TestId = "Saml2Token_DigestTampered",
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
                    new CreateAndValidateParams
                    {
                        ExpectedException = ExpectedException.CryptographicException(),
                        Handler = new Saml2SecurityTokenHandler(),
                        TestId = "Saml2Token_SignatureTampered",
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

        private class DerivedSaml2SecurityTokenHandler : Saml2SecurityTokenHandler
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
