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
using System.IO;
using System.Security.Claims;
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
        public void CanReadToken(SamlTheoryData theoryData)
        {
            TestUtilities.WriteHeader($"{this}.CanReadToken", theoryData);
            try
            {
                // TODO - need to pass actual SamlToken

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
                return new TheoryData<SamlTheoryData>
                {
                    new SamlTheoryData
                    {
                        First = true,
                        CanRead = false,
                        Handler = new SamlSecurityTokenHandler(),
                        TestId = "Null Token",
                        Token = null
                    },

                    new SamlTheoryData
                    {
                        CanRead = false,
                        Handler = new SamlSecurityTokenHandler(),
                        TestId = "DefaultMaximumTokenSizeInBytes + 1",
                        Token = new string('S', TokenValidationParameters.DefaultMaximumTokenSizeInBytes + 2)
                    },

                    new SamlTheoryData
                    {
                        CanRead = true,
                        Handler = new SamlSecurityTokenHandler(),
                        TestId = nameof(ReferenceTokens.SamlToken_Valid),
                        Token = ReferenceTokens.SamlToken_Valid
                    }
                };
            }
        }

        [Theory, MemberData("CreateClaimsIdentitiesTheoryData")]
        public void CreateClaimsIdentities(SamlTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.CreateClaimsIdentities", theoryData);
            try
            {
                var identities = ((theoryData.Handler) as SamlSecurityTokenHandlerPublic).CreateClaimsIdentitiesPublic(theoryData.TokenTestSet.SecurityToken as SamlSecurityToken, theoryData.Issuer, theoryData.ValidationParameters);
                theoryData.ExpectedException.ProcessNoException(context);

                IdentityComparer.AreEqual(identities, theoryData.TokenTestSet.Identities, context);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<SamlTheoryData> CreateClaimsIdentitiesTheoryData
        {
            get
            {
                return new TheoryData<SamlTheoryData>
                {
                    new SamlTheoryData
                    {
                        ExpectedException = new ExpectedException(typeof(SamlSecurityTokenException), "IDX10513:"),
                        First = true,
                        Handler = new SamlSecurityTokenHandlerPublic(),
                        Issuer = Default.Issuer,
                        TestId = nameof(ReferenceSaml.TokenClaimsIdentitiesSubjectEmptyString),
                        TokenTestSet = ReferenceSaml.TokenClaimsIdentitiesSubjectEmptyString,
                        ValidationParameters = new TokenValidationParameters()
                    },
                    new SamlTheoryData
                    {
                        Handler = new SamlSecurityTokenHandlerPublic(),
                        Issuer = Default.Issuer,
                        TestId = nameof(ReferenceSaml.TokenClaimsIdentitiesSameSubject),
                        TokenTestSet = ReferenceSaml.TokenClaimsIdentitiesSameSubject,
                        ValidationParameters = new TokenValidationParameters()
                    },
                    new SamlTheoryData
                    {
                        Handler = new SamlSecurityTokenHandlerPublic(),
                        Issuer = Default.Issuer,
                        TestId = nameof(ReferenceSaml.TokenClaimsIdentitiesDifferentSubjects),
                        TokenTestSet = ReferenceSaml.TokenClaimsIdentitiesDifferentSubjects,
                        ValidationParameters = new TokenValidationParameters()
                    }
                };
            }
        }

        [Theory, MemberData("ReadTokenTheoryData")]
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
                return new TheoryData<SamlTheoryData>
                {
                    new SamlTheoryData
                    {
                        ExpectedException = ExpectedException.NoExceptionExpected,
                        First = true,
                        Handler = new SamlSecurityTokenHandler(),
                        TestId = nameof(ReferenceTokens.SamlToken_Valid),
                        Token = ReferenceTokens.SamlToken_Valid
                    }
                };
            }
        }

        [Theory, MemberData("RoundTripTokenTheoryData")]
        public void RoundTripToken(SamlTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.RoundTripToken", theoryData);
            try
            {
                var samlToken = theoryData.Handler.ReadToken(theoryData.Token);
                var memoryStream = new MemoryStream();
                var writer = XmlDictionaryWriter.CreateTextWriter(memoryStream);
                theoryData.ExpectedException.ProcessNoException(context);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex,context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<SamlTheoryData> RoundTripTokenTheoryData
        {
            get
            {
                return new TheoryData<SamlTheoryData>
                {
                    new SamlTheoryData
                    {
                        ExpectedException = ExpectedException.NoExceptionExpected,
                        First = true,
                        TestId = nameof(ReferenceTokens.SamlToken_Valid),
                        Token = ReferenceTokens.SamlToken_Valid
                    }
                };
            }
        }

        [Theory, MemberData("ValidateAudienceTheoryData")]
        public void ValidateAudience(SamlTheoryData theoryData)
        {
            TestUtilities.WriteHeader($"{this}.ValidateAudience", theoryData);
            try
            {
                ((theoryData.Handler) as SamlSecurityTokenHandlerPublic).ValidateAudiencePublic(theoryData.Audiences, null, theoryData.ValidationParameters);
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
                var tokenTheoryData = new List<TokenTheoryData>();
                ValidateTheoryData.AddValidateAudienceTheoryData(tokenTheoryData);

                var theoryData = new TheoryData<SamlTheoryData>();
                foreach (var item in tokenTheoryData)
                    theoryData.Add(new SamlTheoryData(item)
                    {
                        Handler = new SamlSecurityTokenHandlerPublic()
                    });

                return theoryData;
            }
        }

        [Theory, MemberData("ValidateIssuerTheoryData")]
        public void ValidateIssuer(SamlTheoryData theoryData)
        {
            TestUtilities.WriteHeader($"{this}.ValidateIssuer", theoryData);
            try
            {
                ((theoryData.Handler) as SamlSecurityTokenHandlerPublic).ValidateIssuerPublic(theoryData.Issuer, null, theoryData.ValidationParameters);
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
                var tokenTheoryData = new List<TokenTheoryData>();
                ValidateTheoryData.AddValidateIssuerTheoryData(tokenTheoryData);

                var theoryData = new TheoryData<SamlTheoryData>();
                foreach (var item in tokenTheoryData)
                    theoryData.Add(new SamlTheoryData(item)
                    {
                        Handler = new SamlSecurityTokenHandlerPublic()
                    });

                return theoryData;
            }
        }

        [Theory, MemberData("ValidateTokenTheoryData")]
        public void ValidateToken(SamlTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.ValidateToken", theoryData);

            ClaimsPrincipal retVal = null;
            try
            {
                retVal = (theoryData.Handler as SamlSecurityTokenHandler).ValidateToken(theoryData.Token, theoryData.ValidationParameters, out SecurityToken validatedToken);
                theoryData.ExpectedException.ProcessNoException(context);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<SamlTheoryData> ValidateTokenTheoryData
        {
            get
            {
                // uncomment to view exception displayed to user
                // ExpectedException.DefaultVerbose = true;

                return new TheoryData<SamlTheoryData>
                {
                    new SamlTheoryData
                    {
                        ExpectedException = ExpectedException.ArgumentNullException("IDX10000:"),
                        First = true,
                        Handler = new SamlSecurityTokenHandler(),
                        TestId = "Null-SecurityToken",
                        Token = null,
                        ValidationParameters = new TokenValidationParameters()
                    },
                    new SamlTheoryData
                    {
                        ExpectedException = ExpectedException.ArgumentNullException("IDX10000:"),
                        Handler = new SamlSecurityTokenHandler(),
                        TestId = "NULL-TokenValidationParameters",
                        Token = "s",
                        ValidationParameters = null,
                    },
                    new SamlTheoryData
                    {
                        ExpectedException = ExpectedException.ArgumentException("IDX10209:"),
                        Handler = new SamlSecurityTokenHandler { MaximumTokenSizeInBytes = 1 },
                        TestId = "SecurityTokenTooLarge",
                        Token = "ss",
                        ValidationParameters = new TokenValidationParameters(),
                    },
                    new SamlTheoryData
                    {
                        ExpectedException = new ExpectedException(typeof(SamlSecurityTokenReadException), "IDX11115:"),
                        Handler = new SamlSecurityTokenHandler(),
                        TestId = nameof(ReferenceTokens.SamlToken_MissingMajorVersion),
                        Token = ReferenceTokens.SamlToken_MissingMajorVersion,
                        ValidationParameters = new TokenValidationParameters(),
                    },
                    new SamlTheoryData
                    {
                        ExpectedException = new ExpectedException(typeof(SamlSecurityTokenReadException), "IDX11115:"),
                        Handler = new SamlSecurityTokenHandler(),
                        TestId = nameof(ReferenceTokens.SamlToken_MissingMinorVersion),
                        Token = ReferenceTokens.SamlToken_MissingMinorVersion,
                        ValidationParameters = new TokenValidationParameters(),
                    },
                    new SamlTheoryData
                    {
                        ExpectedException = new ExpectedException(typeof(SamlSecurityTokenReadException), "IDX11116:"),
                        Handler = new SamlSecurityTokenHandler(),
                        TestId = nameof(ReferenceTokens.SamlToken_MajorVersionNotV1),
                        Token = ReferenceTokens.SamlToken_MajorVersionNotV1,
                        ValidationParameters = new TokenValidationParameters(),
                    },
                    new SamlTheoryData
                    {
                        ExpectedException = new ExpectedException(typeof(SamlSecurityTokenReadException), "IDX11117:"),
                        Handler = new SamlSecurityTokenHandler(),
                        TestId = nameof(ReferenceTokens.SamlToken_MinorVersionNotV1),
                        Token = ReferenceTokens.SamlToken_MinorVersionNotV1,
                        ValidationParameters = new TokenValidationParameters(),
                    },
                    new SamlTheoryData
                    {
                        ExpectedException = new ExpectedException(typeof(SamlSecurityTokenReadException), "IDX11115:"),
                        Handler = new SamlSecurityTokenHandler(),
                        TestId = nameof(ReferenceTokens.SamlToken_IdMissing),
                        Token = ReferenceTokens.SamlToken_IdMissing,
                        ValidationParameters = new TokenValidationParameters(),
                    },
                    new SamlTheoryData
                    {
                        ExpectedException = new ExpectedException(typeof(SamlSecurityTokenReadException), "IDX11121:"),
                        Handler = new SamlSecurityTokenHandler(),
                        TestId = nameof(ReferenceTokens.SamlToken_IdFormatError),
                        Token = ReferenceTokens.SamlToken_IdFormatError,
                        ValidationParameters = new TokenValidationParameters(),
                    },
                    new SamlTheoryData
                    {
                        ExpectedException = new ExpectedException(typeof(SamlSecurityTokenReadException), "IDX11115:"),
                        Handler = new SamlSecurityTokenHandler(),
                        TestId = nameof(ReferenceTokens.SamlToken_IssuerMissing),
                        Token = ReferenceTokens.SamlToken_IssuerMissing,
                        ValidationParameters = new TokenValidationParameters(),
                    },
                    new SamlTheoryData
                    {
                        ExpectedException = new ExpectedException(typeof(SamlSecurityTokenReadException), "IDX11115:"),
                        Handler = new SamlSecurityTokenHandler(),
                        TestId = nameof(ReferenceTokens.SamlToken_IssueInstantMissing),
                        Token = ReferenceTokens.SamlToken_IssueInstantMissing,
                        ValidationParameters = new TokenValidationParameters(),
                    },
                    new SamlTheoryData
                    {
                        ExpectedException = new ExpectedException(typeof(SamlSecurityTokenReadException), "IDX11122:", typeof(FormatException)),
                        Handler = new SamlSecurityTokenHandler(),
                        TestId = nameof(ReferenceTokens.SamlToken_IssueInstantFormatError),
                        Token = ReferenceTokens.SamlToken_IssueInstantFormatError,
                        ValidationParameters = new TokenValidationParameters(),
                    },
                    new SamlTheoryData
                    {
                        ExpectedException = new ExpectedException(typeof(SamlSecurityTokenReadException), "IDX11120:"),
                        Handler = new SamlSecurityTokenHandler(),
                        TestId = nameof(ReferenceTokens.SamlToken_AudienceMissing),
                        Token = ReferenceTokens.SamlToken_AudienceMissing,
                        ValidationParameters = new TokenValidationParameters(),
                    },
                    new SamlTheoryData
                    {
                        ExpectedException = new ExpectedException(typeof(SamlSecurityTokenReadException), "IDX11130:"),
                        Handler = new SamlSecurityTokenHandler(),
                        TestId = nameof(ReferenceTokens.SamlToken_NoStatements),
                        Token = ReferenceTokens.SamlToken_NoStatements,
                        ValidationParameters = new TokenValidationParameters(),
                    },
                    new SamlTheoryData
                    {
                        ExpectedException = new ExpectedException(typeof(SamlSecurityTokenReadException), "IDX21011:", typeof(XmlReadException)),
                        Handler = new SamlSecurityTokenHandler(),
                        TestId = nameof(ReferenceTokens.SamlToken_NoSubject),
                        Token = ReferenceTokens.SamlToken_NoSubject,
                        ValidationParameters = new TokenValidationParameters(),
                    },
                    new SamlTheoryData
                    {
                        ExpectedException = new ExpectedException(typeof(SamlSecurityTokenReadException), "IDX11131:"),
                        Handler = new SamlSecurityTokenHandler(),
                        TestId = nameof(ReferenceTokens.SamlToken_NoAttributes),
                        Token = ReferenceTokens.SamlToken_NoAttributes,
                        ValidationParameters = new TokenValidationParameters(),
                    },
                    new SamlTheoryData
                    {
                        ExpectedException = new ExpectedException(typeof(SecurityTokenInvalidSignatureException), "IDX21210:"),
                        Handler = new SamlSecurityTokenHandler()
                        {
                            TransformFactory = ReferenceTransformFactory.TransformFactoryAlwaysUnsupported
                        },
                        TestId = nameof(ReferenceTransformFactory.TransformFactoryAlwaysUnsupported),
                        Token = ReferenceTokens.SamlToken_Valid,
                        ValidationParameters = new TokenValidationParameters()
                        {
                            IssuerSigningKey = ReferenceXml.DefaultAADSigningKey
                        }
                    },
                    new SamlTheoryData
                    {
                        ExpectedException = new ExpectedException(typeof(SecurityTokenInvalidSignatureException), "IDX21210:"),
                        Handler = new SamlSecurityTokenHandler()
                        {
                            TransformFactory = ReferenceTransformFactory.TransformFactoryTransformAlwaysUnsupported
                        },
                        TestId = nameof(ReferenceTransformFactory.TransformFactoryTransformAlwaysUnsupported),
                        Token = ReferenceTokens.SamlToken_Valid,
                        ValidationParameters = new TokenValidationParameters()
                        {
                            IssuerSigningKey = ReferenceXml.DefaultAADSigningKey
                        }
                    },
                    new SamlTheoryData
                    {
                        ExpectedException = new ExpectedException(typeof(SecurityTokenInvalidSignatureException), "IDX21211:"),
                        Handler = new SamlSecurityTokenHandler()
                        {
                            TransformFactory = ReferenceTransformFactory.TransformFactoryCanonicalizingTransformAlwaysUnsupported
                        },
                        TestId = nameof(ReferenceTransformFactory.TransformFactoryCanonicalizingTransformAlwaysUnsupported),
                        Token = ReferenceTokens.SamlToken_Valid,
                        ValidationParameters = new TokenValidationParameters()
                        {
                            IssuerSigningKey = ReferenceXml.DefaultAADSigningKey
                        }
                    }
                };
            }
        }

        [Theory, MemberData("WriteTokenTheoryData")]
        public void WriteToken(SamlTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.WriteToken", theoryData);
            try
            {
                var xml = (theoryData.Handler as SamlSecurityTokenHandler).WriteToken(theoryData.TokenTestSet.SecurityToken);
                theoryData.ExpectedException.ProcessNoException(context);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<SamlTheoryData> WriteTokenTheoryData
        {
            get
            {
                // uncomment to view exception displayed to user
                // ExpectedException.DefaultVerbose = true;
                return new TheoryData<SamlTheoryData>
                {
                    new SamlTheoryData
                    {
                        ExpectedException = ExpectedException.ArgumentNullException("token"),
                        First = true,
                        TestId = nameof(ReferenceSaml.NullToken),
                        TokenTestSet = ReferenceSaml.NullToken
                    },
                    new SamlTheoryData
                    {
                        ExpectedException = ExpectedException.ArgumentException("IDX10400:"),
                        TestId = nameof(ReferenceSaml.JwtToken),
                        TokenTestSet = ReferenceSaml.JwtToken
                    }
                };
            }
        }

        [Theory, MemberData("WriteTokenXmlTheoryData")]
        public void WriteTokenXml(SamlTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.WriteTokenXml", theoryData);
            try
            {
                (theoryData.Handler as SamlSecurityTokenHandler).WriteToken(theoryData.XmlWriter, theoryData.TokenTestSet.SecurityToken);
                theoryData.ExpectedException.ProcessNoException(context);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<SamlTheoryData> WriteTokenXmlTheoryData
        {
            get
            {
                // uncomment to view exception displayed to user
                // ExpectedException.DefaultVerbose = true;

                var theoryData = new TheoryData<SamlTheoryData>();
                var memoryStream = new MemoryStream();
                theoryData.Add(new SamlTheoryData
                {
                    ExpectedException = ExpectedException.ArgumentNullException("token"),
                    First = true,
                    TestId = nameof(ReferenceSaml.NullToken),
                    TokenTestSet = ReferenceSaml.NullToken,
                    XmlWriter = XmlDictionaryWriter.CreateTextWriter(memoryStream)
                });

                theoryData.Add(new SamlTheoryData
                {
                    ExpectedException = ExpectedException.ArgumentNullException("writer"),
                    TestId = "Null XmlWriter",
                    TokenTestSet = ReferenceSaml.SamlSecurityTokenValid
                });

                memoryStream = new MemoryStream();
                theoryData.Add(new SamlTheoryData
                {
                    ExpectedException = ExpectedException.ArgumentException("IDX10400:"),
                    MemoryStream = memoryStream,
                    TestId = nameof(ReferenceSaml.JwtToken),
                    TokenTestSet = ReferenceSaml.JwtToken,
                    XmlWriter = XmlDictionaryWriter.CreateTextWriter(memoryStream)
                });

                return theoryData;
            }
        }

#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant

        private class SamlSecurityTokenHandlerPublic : SamlSecurityTokenHandler
        {
            public IEnumerable<ClaimsIdentity> CreateClaimsIdentitiesPublic(SamlSecurityToken samlToken, string issuer, TokenValidationParameters validationParameters)
            {
                return base.CreateClaimsIdentities(samlToken, issuer, validationParameters);
            }

            public void ValidateAudiencePublic(IEnumerable<string> audiences, SecurityToken token, TokenValidationParameters validationParameters)
            {
                base.ValidateAudience(audiences, token, validationParameters);
            }

            public string ValidateIssuerPublic(string issuer, SecurityToken token, TokenValidationParameters validationParameters)
            {
                return base.ValidateIssuer(issuer, token, validationParameters);
            }
        }
    }
}
