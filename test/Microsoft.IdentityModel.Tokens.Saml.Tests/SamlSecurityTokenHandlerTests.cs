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
using System.Text;
using System.Xml;
using Microsoft.IdentityModel.Tests;
using Microsoft.IdentityModel.Xml;
using Xunit;

namespace Microsoft.IdentityModel.Tokens.Saml.Tests
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
                var handler = new SamlSecurityTokenHandler();
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
                        TestId = nameof(RefrenceTokens.SamlToken_Valid),
                        Token = RefrenceTokens.SamlToken_Valid
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
                    Handler = new SamlSecurityTokenHandler(),
                    TestId = nameof(RefrenceTokens.SamlToken_Valid),
                    Token = RefrenceTokens.SamlToken_Valid
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
                ((theoryData.Handler) as DerivedSamlSecurityTokenHandler).ValidateAudiencePublic(theoryData.Audiences, null, theoryData.ValidationParameters);
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
                var handler = new DerivedSamlSecurityTokenHandler();

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
                ((theoryData.Handler) as DerivedSamlSecurityTokenHandler).ValidateIssuerPublic(theoryData.Issuer, null, theoryData.ValidationParameters);
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
                var handler = new DerivedSamlSecurityTokenHandler();

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
                retVal = (theoryData.Handler as SamlSecurityTokenHandler).ValidateToken(theoryData.Token, theoryData.ValidationParameters, out SecurityToken validatedToken);
                theoryData.ExpectedException.ProcessNoException();
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex);
            }
        }

//#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant
//        [Theory, MemberData("ValidateTokenTheoryData")]
//#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
//        public void ValidateToken(SamlTheoryData theoryData)
//        {
//            TestUtilities.WriteHeader($"{this}.ValidateToken", theoryData);

//            ClaimsPrincipal retVal = null;
//            try
//            {
//                retVal = (theoryData.Handler as SamlSecurityTokenHandler).ValidateToken(theoryData.Token, theoryData.ValidationParameters, out SecurityToken validatedToken);
//                theoryData.ExpectedException.ProcessNoException();
//            }
//            catch (Exception ex)
//            {
//                theoryData.ExpectedException.ProcessException(ex);
//            }
//        }

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
                        Handler = new SamlSecurityTokenHandler(),
                        TestId = "Null-SecurityToken",
                        Token = null,
                        ValidationParameters = new TokenValidationParameters()
                    });

                theoryData.Add(
                    new SamlTheoryData
                    {
                        ExpectedException = ExpectedException.ArgumentNullException("IDX10000:"),
                        Handler = new SamlSecurityTokenHandler(),
                        TestId = "NULL-TokenValidationParameters",
                        Token = "s",
                        ValidationParameters = null,
                    });

                var tokenHandler = new SamlSecurityTokenHandler();
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
                        ExpectedException = new ExpectedException(typeof(SamlSecurityTokenReadException), "IDX11115:"),
                        Handler = new SamlSecurityTokenHandler(),
                        TestId = nameof(RefrenceTokens.SamlToken_MissingMajorVersion),
                        Token = RefrenceTokens.SamlToken_MissingMajorVersion,
                        ValidationParameters = new TokenValidationParameters(),
                    });

                theoryData.Add(
                    new SamlTheoryData
                    {
                        ExpectedException = new ExpectedException(typeof(SamlSecurityTokenReadException), "IDX11115:"),
                        Handler = new SamlSecurityTokenHandler(),
                        TestId = nameof(RefrenceTokens.SamlToken_MissingMinorVersion),
                        Token = RefrenceTokens.SamlToken_MissingMinorVersion,
                        ValidationParameters = new TokenValidationParameters(),
                    });

                theoryData.Add(
                    new SamlTheoryData
                    {
                        ExpectedException = new ExpectedException(typeof(SamlSecurityTokenReadException), "IDX11116:"),
                        Handler = new SamlSecurityTokenHandler(),
                        TestId = nameof(RefrenceTokens.SamlToken_MajorVersionNotV1),
                        Token = RefrenceTokens.SamlToken_MajorVersionNotV1,
                        ValidationParameters = new TokenValidationParameters(),
                    });

                theoryData.Add(
                    new SamlTheoryData
                    {
                        ExpectedException = new ExpectedException(typeof(SamlSecurityTokenReadException), "IDX11117:"),
                        Handler = new SamlSecurityTokenHandler(),
                        TestId = nameof(RefrenceTokens.SamlToken_MinorVersionNotV1),
                        Token = RefrenceTokens.SamlToken_MinorVersionNotV1,
                        ValidationParameters = new TokenValidationParameters(),
                    });

                theoryData.Add(
                    new SamlTheoryData
                    {
                        ExpectedException = new ExpectedException(typeof(SamlSecurityTokenReadException), "IDX11115:"),
                        Handler = new SamlSecurityTokenHandler(),
                        TestId = nameof(RefrenceTokens.SamlToken_IdMissing),
                        Token = RefrenceTokens.SamlToken_IdMissing,
                        ValidationParameters = new TokenValidationParameters(),
                    });

                theoryData.Add(
                    new SamlTheoryData
                    {
                        ExpectedException = new ExpectedException(typeof(SamlSecurityTokenReadException), "IDX11121:"),
                        Handler = new SamlSecurityTokenHandler(),
                        TestId = nameof(RefrenceTokens.SamlToken_IdFormatError),
                        Token = RefrenceTokens.SamlToken_IdFormatError,
                        ValidationParameters = new TokenValidationParameters(),
                    });


                theoryData.Add(
                    new SamlTheoryData
                    {
                        ExpectedException = new ExpectedException(typeof(SamlSecurityTokenReadException), "IDX11115:"),
                        Handler = new SamlSecurityTokenHandler(),
                        TestId = nameof(RefrenceTokens.SamlToken_IssuerMissing),
                        Token = RefrenceTokens.SamlToken_IssuerMissing,
                        ValidationParameters = new TokenValidationParameters(),
                    });

                theoryData.Add(
                    new SamlTheoryData
                    {
                        ExpectedException = new ExpectedException(typeof(SamlSecurityTokenReadException), "IDX11115:"),
                        Handler = new SamlSecurityTokenHandler(),
                        TestId = nameof(RefrenceTokens.SamlToken_IssuerInstantMissing),
                        Token = RefrenceTokens.SamlToken_IssuerInstantMissing,
                        ValidationParameters = new TokenValidationParameters(),
                    });

                theoryData.Add(
                    new SamlTheoryData
                    {
                        ExpectedException = new ExpectedException(typeof(SamlSecurityTokenReadException), "IDX11122:", typeof(FormatException)),
                        Handler = new SamlSecurityTokenHandler(),
                        TestId = nameof(RefrenceTokens.SamlToken_IssuerInstantFormatError),
                        Token = RefrenceTokens.SamlToken_IssuerInstantFormatError,
                        ValidationParameters = new TokenValidationParameters(),
                    });

                theoryData.Add(
                    new SamlTheoryData
                    {
                        ExpectedException = new ExpectedException(typeof(SamlSecurityTokenReadException), "IDX11120:"),
                        Handler = new SamlSecurityTokenHandler(),
                        TestId = nameof(RefrenceTokens.SamlToken_AudienceMissing),
                        Token = RefrenceTokens.SamlToken_AudienceMissing,
                        ValidationParameters = new TokenValidationParameters(),
                    });

                theoryData.Add(
                    new SamlTheoryData
                    {
                        ExpectedException = new ExpectedException(typeof(SamlSecurityTokenReadException), "IDX11130:"),
                        Handler = new SamlSecurityTokenHandler(),
                        TestId = nameof(RefrenceTokens.SamlToken_NoStatements),
                        Token = RefrenceTokens.SamlToken_NoStatements,
                        ValidationParameters = new TokenValidationParameters(),
                    });

                theoryData.Add(
                    new SamlTheoryData
                    {
                        ExpectedException = new ExpectedException(typeof(SamlSecurityTokenReadException), "IDX21011:", typeof(XmlReadException)),
                        Handler = new SamlSecurityTokenHandler(),
                        TestId = nameof(RefrenceTokens.SamlToken_NoSubject),
                        Token = RefrenceTokens.SamlToken_NoSubject,
                        ValidationParameters = new TokenValidationParameters(),
                    });

                theoryData.Add(
                    new SamlTheoryData
                    {
                        ExpectedException = new ExpectedException(typeof(SamlSecurityTokenReadException), "IDX11131:"),
                        Handler = new SamlSecurityTokenHandler(),
                        TestId = nameof(RefrenceTokens.SamlToken_NoAttributes),
                        Token = RefrenceTokens.SamlToken_NoAttributes,
                        ValidationParameters = new TokenValidationParameters(),
                    });

                //var keySet = new JsonWebKeySet(RefrenceTokens.AADJWKS);
                //var certData = "MIIDBTCCAe2gAwIBAgIQY4RNIR0dX6dBZggnkhCRoDANBgkqhkiG9w0BAQsFADAtMSswKQYDVQQDEyJhY2NvdW50cy5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MB4XDTE3MDIxMzAwMDAwMFoXDTE5MDIxNDAwMDAwMFowLTErMCkGA1UEAxMiYWNjb3VudHMuYWNjZXNzY29udHJvbC53aW5kb3dzLm5ldDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMBEizU1OJms31S/ry7iav/IICYVtQ2MRPhHhYknHImtU03sgVk1Xxub4GD7R15i9UWIGbzYSGKaUtGU9lP55wrfLpDjQjEgaXi4fE6mcZBwa9qc22is23B6R67KMcVyxyDWei+IP3sKmCcMX7Ibsg+ubZUpvKGxXZ27YgqFTPqCT2znD7K81YKfy+SVg3uW6epW114yZzClTQlarptYuE2mujxjZtx7ZUlwc9AhVi8CeiLwGO1wzTmpd/uctpner6oc335rvdJikNmc1cFKCK+2irew1bgUJHuN+LJA0y5iVXKvojiKZ2Ii7QKXn19Ssg1FoJ3x2NWA06wc0CnruLsCAwEAAaMhMB8wHQYDVR0OBBYEFDAr/HCMaGqmcDJa5oualVdWAEBEMA0GCSqGSIb3DQEBCwUAA4IBAQAiUke5mA86R/X4visjceUlv5jVzCn/SIq6Gm9/wCqtSxYvifRXxwNpQTOyvHhrY/IJLRUp2g9/fDELYd65t9Dp+N8SznhfB6/Cl7P7FRo99rIlj/q7JXa8UB/vLJPDlr+NREvAkMwUs1sDhL3kSuNBoxrbLC5Jo4es+juQLXd9HcRraE4U3UZVhUS2xqjFOfaGsCbJEqqkjihssruofaxdKT1CPzPMANfREFJznNzkpJt4H0aMDgVzq69NxZ7t1JiIuc43xRjeiixQMRGMi1mAB75fTyfFJ/rWQ5J/9kh0HMZVtHsqICBF1tHMTMIK5rwoweY0cuCIpN7A/zMOQtoD";
                //var aadCert = new X509Certificate2(Convert.FromBase64String(certData));
                //theoryData.Add(
                //    new SamlTheoryData
                //    {
                //        ExpectedException = ExpectedException.NoExceptionExpected,
                //        Handler = new SamlSecurityTokenHandler(),
                //       // TestId = $"{nameof(RefrenceTokens.SamlToken_Valid)} IssuerSigningKey set",
                //        TestId = nameof(RefrenceTokens.SamlToken_Valid),
                //        Token = RefrenceTokens.SamlToken_Valid,
                //        ValidationParameters = new TokenValidationParameters
                //        {
                //            IssuerSigningKey = new X509SecurityKey(aadCert),
                //            IssuerSigningKeys = keySet.GetSigningKeys(),
                //            ValidateIssuer = false,
                //            ValidateAudience = false,
                //            ValidateLifetime = false,
                //        }
                //    });

                //theoryData.Add(
                //    new SamlTheoryData
                //    {
                //        ExpectedException = ExpectedException.NoExceptionExpected,
                //        Handler = new SamlSecurityTokenHandler(),
                //        TestId = nameof(RefrenceTokens.Saml2Token_Valid_Spaces_Added),
                //        Token = RefrenceTokens.Saml2Token_Valid_Spaces_Added,
                //        ValidationParameters = new TokenValidationParameters
                //        {
                //            IssuerSigningKey = new X509SecurityKey(aadCert),
                //            IssuerSigningKeys = keySet.GetSigningKeys(),
                //            ValidateIssuer = false,
                //            ValidateAudience = false,
                //            ValidateLifetime = false,
                //        }
                //    });


                //theoryData.Add(
                //    new SamlTheoryData
                //    {
                //        ExpectedException = ExpectedException.SecurityTokenInvalidSignatureException("IDX10503:"),
                //        Handler = new SamlSecurityTokenHandler(),
                //        TestId = nameof(RefrenceTokens.Saml2Token_Formated),
                //        Token = RefrenceTokens.Saml2Token_Formated,
                //        ValidationParameters = new TokenValidationParameters
                //        {
                //            IssuerSigningKey = new X509SecurityKey(aadCert),
                //            IssuerSigningKeys = keySet.GetSigningKeys(),
                //            ValidateIssuer = false,
                //            ValidateAudience = false,
                //            ValidateLifetime = false,
                //        }
                //    });

                //theoryData.Add(
                //    new SamlTheoryData
                //    {
                //        ExpectedException = ExpectedException.SecurityTokenInvalidSignatureException("IDX10503:"),
                //        Handler = new SamlSecurityTokenHandler(),
                //        TestId = nameof(RefrenceTokens.Saml2Token_AttributeTampered),
                //        Token = RefrenceTokens.Saml2Token_AttributeTampered,
                //        ValidationParameters = new TokenValidationParameters
                //        {
                //            IssuerSigningKey = new X509SecurityKey(aadCert),
                //            IssuerSigningKeys = keySet.GetSigningKeys(),
                //            ValidateIssuer = false,
                //            ValidateAudience = false,
                //            ValidateLifetime = false,
                //        }
                //    });

                //theoryData.Add(
                //    new SamlTheoryData
                //    {
                //        ExpectedException = ExpectedException.SecurityTokenInvalidSignatureException("IDX10503:"),
                //        Handler = new SamlSecurityTokenHandler(),
                //        TestId = nameof(RefrenceTokens.Saml2Token_DigestTampered),
                //        Token = RefrenceTokens.Saml2Token_DigestTampered,
                //        ValidationParameters = new TokenValidationParameters
                //        {
                //            IssuerSigningKey = new X509SecurityKey(aadCert),
                //            IssuerSigningKeys = keySet.GetSigningKeys(),
                //            ValidateIssuer = false,
                //            ValidateAudience = false,
                //            ValidateLifetime = false,
                //        }
                //    });

                //theoryData.Add(
                //    new SamlTheoryData
                //    {
                //        ExpectedException = ExpectedException.SecurityTokenSignatureKeyNotFoundException("IDX10501:"),
                //        Handler = new SamlSecurityTokenHandler(),
                //        TestId = nameof(RefrenceTokens.Saml2Token_AttributeTampered_NoKeyMatch),
                //        Token = RefrenceTokens.Saml2Token_AttributeTampered_NoKeyMatch,
                //        ValidationParameters = new TokenValidationParameters
                //        {
                //            IssuerSigningKey = new X509SecurityKey(aadCert),
                //            IssuerSigningKeys = keySet.GetSigningKeys(),
                //            ValidateIssuer = false,
                //            ValidateAudience = false,
                //            ValidateLifetime = false,
                //        }
                //    });


                //theoryData.Add(
                //    new SamlTheoryData
                //    {
                //        ExpectedException = ExpectedException.SecurityTokenInvalidSignatureException("IDX10503:"),
                //        Handler = new SamlSecurityTokenHandler(),
                //        TestId = nameof(RefrenceTokens.Saml2Token_SignatureTampered),
                //        Token = RefrenceTokens.Saml2Token_SignatureTampered,
                //        ValidationParameters = new TokenValidationParameters
                //        {
                //            IssuerSigningKey = new X509SecurityKey(aadCert),
                //            IssuerSigningKeys = keySet.GetSigningKeys(),
                //            ValidateIssuer = false,
                //            ValidateAudience = false,
                //            ValidateLifetime = false,
                //        }
                //    });

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

        private class DerivedSamlSecurityTokenHandler : SamlSecurityTokenHandler
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
    }
}
