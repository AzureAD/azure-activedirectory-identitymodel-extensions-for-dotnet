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
using Microsoft.IdentityModel.Tests;
using Microsoft.IdentityModel.Tokens.Saml2;
using Microsoft.IdentityModel.Xml;
using Xunit;

#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant

namespace Microsoft.IdentityModel.Tokens.Saml.Tests
{
    public class Saml2SecurityTokenHandlerTests
    {
        [Fact]
        public void Constructors()
        {
            var saml2SecurityTokenHandler = new Saml2SecurityTokenHandler();
        }

        [Fact]
        public void Defaults()
        {
            var samlSecurityTokenHandler = new Saml2SecurityTokenHandler();
            Assert.True(samlSecurityTokenHandler.MaximumTokenSizeInBytes == TokenValidationParameters.DefaultMaximumTokenSizeInBytes, "MaximumTokenSizeInBytes");
        }

        [Fact]
        public void GetSets()
        {
            var samlSecurityTokenHandler = new Saml2SecurityTokenHandler();
            TestUtilities.SetGet(samlSecurityTokenHandler, "MaximumTokenSizeInBytes", (object)0, ExpectedException.ArgumentOutOfRangeException("IDX10101:"));
            TestUtilities.SetGet(samlSecurityTokenHandler, "MaximumTokenSizeInBytes", (object)1, ExpectedException.NoExceptionExpected);
            TestUtilities.SetGet(samlSecurityTokenHandler, "Serializer", null, ExpectedException.ArgumentNullException());

            samlSecurityTokenHandler = new Saml2SecurityTokenHandler();
            var context = new GetSetContext
            {
                PropertyNamesAndSetGetValue = new List<KeyValuePair<string, List<object>>>
                {
                    new KeyValuePair<string, List<object>>("MaximumTokenSizeInBytes", new List<object>{(object)TokenValidationParameters.DefaultMaximumTokenSizeInBytes, (object)1000, (object)10}),
                    new KeyValuePair<string, List<object>>("SetDefaultTimesOnTokenCreation", new List<object>{true, false, true}),
                    new KeyValuePair<string, List<object>>("TokenLifetimeInMinutes", new List<object>{(object)60, (object)1000, (object)10}),
                },
                Object = samlSecurityTokenHandler
            };

            TestUtilities.GetSet(context);
            TestUtilities.AssertFailIfErrors("Saml2SecurityTokenHandlerTests_GetSets", context.Errors);
        }

        [Theory, MemberData(nameof(CanReadTokenTheoryData))]
        public void CanReadToken(Saml2TheoryData theoryData)
        {
            TestUtilities.WriteHeader($"{this}.CanReadToken", theoryData);
            var context = new CompareContext($"{this}.CanReadToken, {theoryData}");
            try
            {
                // TODO - need to pass actual Saml2Token

                if (theoryData.CanRead != theoryData.Handler.CanReadToken(theoryData.Token))
                    Assert.False(true, $"Expected CanRead != CanRead, token: {theoryData.Token}");

                theoryData.ExpectedException.ProcessNoException(context);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<Saml2TheoryData> CanReadTokenTheoryData
        {
            get =>  new TheoryData<Saml2TheoryData>
            {
                new Saml2TheoryData
                {
                    CanRead = false,
                    First = true,
                    Handler = new Saml2SecurityTokenHandler(),
                    TestId = "Null Token",
                    Token = null
                },
                new Saml2TheoryData
                {
                    CanRead = false,
                    Handler = new Saml2SecurityTokenHandler(),
                    TestId = "DefaultMaximumTokenSizeInBytes + 1",
                    Token = new string('S', TokenValidationParameters.DefaultMaximumTokenSizeInBytes + 2)
                },
                new Saml2TheoryData
                {
                    CanRead = true,
                    Handler = new Saml2SecurityTokenHandler(),
                    TestId = nameof(ReferenceTokens.Saml2Token_Valid),
                    Token = ReferenceTokens.Saml2Token_Valid
                },
                new Saml2TheoryData
                {
                    CanRead = false,
                    Handler = new Saml2SecurityTokenHandler(),
                    TestId = nameof(ReferenceTokens.SamlToken_Valid),
                    Token = ReferenceTokens.SamlToken_Valid
                }
            };
        }

        [Theory, MemberData(nameof(ConsolidateAttributesTheoryData))]
        public void ConsolidateAttributes(Saml2TheoryData theoryData)
        {
            TestUtilities.WriteHeader($"{this}.ConsolidateAttributes", theoryData);
            var context = new CompareContext($"{this}.ConsolidateAttributes, {theoryData}");
            var handler = theoryData.Handler as Saml2SecurityTokenHandlerPublic;
            try
            {
                var consolidatedAttributes = handler.ConsolidateAttributesPublic(theoryData.Attributes);
                theoryData.ExpectedException.ProcessNoException(context);
                IdentityComparer.AreEnumsEqual(consolidatedAttributes, theoryData.ConsolidatedAttributes, context, AreSaml2AttributesEqual);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<Saml2TheoryData> ConsolidateAttributesTheoryData
        {
            get
            {
                var theoryData = new TheoryData<Saml2TheoryData>
                {
                    new Saml2TheoryData
                    {
                        ExpectedException = ExpectedException.ArgumentNullException(),
                        First = true,
                        TestId = "param attributes null"
                    },
                    new Saml2TheoryData
                    {
                        Attributes = new List<Saml2Attribute>(),
                        ConsolidatedAttributes = new List<Saml2Attribute>(),
                        TestId = "Empty Attribute List"
                    },
                    new Saml2TheoryData
                    {
                        Attributes = new List<Saml2Attribute>
                        {
                            Default.Saml2AttributeSingleValue
                        },
                        ConsolidatedAttributes = new List<Saml2Attribute>
                        {
                            Default.Saml2AttributeSingleValue
                        },
                        TestId = nameof(Default.Saml2AttributeSingleValue)
                    },
                    new Saml2TheoryData
                    {
                        Attributes = new List<Saml2Attribute>
                        {
                            Default.Saml2AttributeSingleValue,
                            Default.Saml2AttributeSingleValue
                        },
                        ConsolidatedAttributes = new List<Saml2Attribute>
                        {
                            Default.Saml2AttributeMultiValue
                        },
                        TestId = nameof(Default.Saml2AttributeMultiValue)
                    }
                };

                var attribute = Default.Saml2AttributeSingleValue;
                attribute.AttributeValueXsiType = Guid.NewGuid().ToString();
                theoryData.Add(CreateAttributeTheoryData(attribute, "AttributeValueXsiType"));

                attribute = Default.Saml2AttributeSingleValue;
                attribute.FriendlyName = Guid.NewGuid().ToString();
                theoryData.Add(CreateAttributeTheoryData(attribute, "FriendlyName"));

                attribute = new Saml2Attribute(Guid.NewGuid().ToString(), Guid.NewGuid().ToString());
                theoryData.Add(CreateAttributeTheoryData(attribute, "Name, Value"));

                attribute = Default.Saml2AttributeSingleValue;
                attribute.NameFormat = new Uri(Default.ReferenceUri);
                theoryData.Add(CreateAttributeTheoryData(attribute, "NameFormat"));

                attribute = Default.Saml2AttributeSingleValue;
                attribute.OriginalIssuer = NotDefault.OriginalIssuer;
                theoryData.Add(CreateAttributeTheoryData(attribute, "OrginalIssuer"));

                return theoryData;
            }
        }

        private static Saml2TheoryData CreateAttributeTheoryData(Saml2Attribute attribute, string testId)
        {
            return new Saml2TheoryData
            {
                Attributes = new List<Saml2Attribute>
                {
                    Default.Saml2AttributeSingleValue,
                    attribute,
                    Default.Saml2AttributeSingleValue,
                },
                ConsolidatedAttributes = new List<Saml2Attribute>
                {
                    Default.Saml2AttributeMultiValue,
                    attribute
                },
                TestId = testId
            };
        }

        public static bool AreSaml2AttributesEqual(Saml2Attribute attribute1, Saml2Attribute attribute2, CompareContext context)
        {
            var localContext = new CompareContext("AreSaml2AttributesEqual");
            if (!IdentityComparer.ContinueCheckingEquality(attribute1, attribute2, localContext))
                return context.Merge(localContext);

            IdentityComparer.AreStringsEqual(attribute1.AttributeValueXsiType, attribute2.AttributeValueXsiType, localContext);
            IdentityComparer.AreStringsEqual(attribute1.FriendlyName, attribute2.FriendlyName, localContext);
            IdentityComparer.AreStringsEqual(attribute1.Name, attribute2.Name, localContext);
            IdentityComparer.AreStringsEqual(attribute1.NameFormat?.AbsoluteUri, attribute2.NameFormat?.AbsoluteUri, localContext);
            IdentityComparer.AreStringsEqual(attribute1.OriginalIssuer, attribute2.OriginalIssuer, localContext);

            return context.Merge(localContext);
        }

        [Theory, MemberData(nameof(ReadTokenTheoryData))]
        public void ReadToken(Saml2TheoryData theoryData)
        {
            TestUtilities.WriteHeader($"{this}.ReadToken", theoryData);
            var context = new CompareContext($"{this}.ReadToken, {theoryData}");
            try
            {
                theoryData.Handler.ReadToken(theoryData.Token);
                theoryData.ExpectedException.ProcessNoException(context);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<Saml2TheoryData> ReadTokenTheoryData
        {
            get
            {
                var theoryData = new TheoryData<Saml2TheoryData>();

                theoryData.Add(new Saml2TheoryData
                {
                    ExpectedException = ExpectedException.NoExceptionExpected,
                    First = true,
                    Handler = new Saml2SecurityTokenHandler(),
                    TestId = nameof(ReferenceTokens.Saml2Token_Valid),
                    Token = ReferenceTokens.Saml2Token_Valid
                });

                return theoryData;
            }
        }

        [Theory, MemberData(nameof(RoundTripTokenTheoryData))]
        public void RoundTripToken(Saml2TheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.RoundTripToken", theoryData);
            try
            {
                var samlToken = theoryData.Handler.CreateToken(theoryData.TokenDescriptor);
                var token = theoryData.Handler.WriteToken(samlToken);
                var principal = theoryData.Handler.ValidateToken(token, theoryData.ValidationParameters, out SecurityToken validatedToken);
                theoryData.ExpectedException.ProcessNoException(context);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<Saml2TheoryData> RoundTripTokenTheoryData
        {
            get =>  new TheoryData<Saml2TheoryData>
            {
                new Saml2TheoryData
                {
                    First = true,
                    TestId = nameof(Default.ClaimsIdentity),
                    TokenDescriptor = new SecurityTokenDescriptor
                    {
                        Expires = DateTime.UtcNow + TimeSpan.FromDays(1),
                        Audience = Default.Audience,
                        SigningCredentials = Default.AsymmetricSigningCredentials,
                        Issuer = Default.Issuer,
                        Subject = Default.ClaimsIdentity
                    },
                    ValidationParameters = new TokenValidationParameters
                    {
                        IssuerSigningKey = Default.AsymmetricSigningKey,
                        ValidAudience = Default.Audience,
                        ValidIssuer = Default.Issuer,
                    }
                },
                new Saml2TheoryData
                {
                    TestId = nameof(Default.ClaimsIdentity) + nameof(KeyingMaterial.RSASigningCreds_2048),
                    TokenDescriptor = new SecurityTokenDescriptor
                    {
                        Expires = DateTime.UtcNow + TimeSpan.FromDays(1),
                        Audience = Default.Audience,
                        SigningCredentials = KeyingMaterial.RSASigningCreds_2048,
                        Issuer = Default.Issuer,
                        Subject = Default.ClaimsIdentity
                    },
                    ValidationParameters = new TokenValidationParameters
                    {
                        IssuerSigningKey = KeyingMaterial.RSASigningCreds_2048_Public.Key,
                        ValidAudience = Default.Audience,
                        ValidIssuer = Default.Issuer,
                    },
                },
                new Saml2TheoryData
                {
                    TestId = nameof(Default.ClaimsIdentity) + nameof(KeyingMaterial.RSASigningCreds_2048_FromRsa),
                    TokenDescriptor = new SecurityTokenDescriptor
                    {
                        Expires = DateTime.UtcNow + TimeSpan.FromDays(1),
                        Audience = Default.Audience,
                        SigningCredentials = KeyingMaterial.RSASigningCreds_2048_FromRsa,
                        Issuer = Default.Issuer,
                        Subject = Default.ClaimsIdentity
                    },
                    ValidationParameters = new TokenValidationParameters
                    {
                        IssuerSigningKey = KeyingMaterial.RSASigningCreds_2048_FromRsa_Public.Key,
                        ValidAudience = Default.Audience,
                        ValidIssuer = Default.Issuer,
                    },
                },
                new Saml2TheoryData
                {
                    TestId = nameof(Default.ClaimsIdentity) + nameof(KeyingMaterial.JsonWebKeyRsa256SigningCredentials),
                    TokenDescriptor = new SecurityTokenDescriptor
                    {
                        Expires = DateTime.UtcNow + TimeSpan.FromDays(1),
                        Audience = Default.Audience,
                        SigningCredentials = KeyingMaterial.JsonWebKeyRsa256SigningCredentials,
                        Issuer = Default.Issuer,
                        Subject = Default.ClaimsIdentity
                    },
                    ValidationParameters = new TokenValidationParameters
                    {
                        IssuerSigningKey = KeyingMaterial.JsonWebKeyRsa256PublicSigningCredentials.Key,
                        ValidAudience = Default.Audience,
                        ValidIssuer = Default.Issuer,
                    }
                }
            };
        }

        [Theory, MemberData(nameof(RoundTripActorTheoryData))]
        public void RoundTripActor(Saml2TheoryData theoryData)
        {
            TestUtilities.WriteHeader($"{this}.RoundTripActor", theoryData);
            CompareContext context = new CompareContext($"{this}.RoundTripActor, {theoryData}");

            var handler = theoryData.Handler as Saml2SecurityTokenHandlerPublic;
            var actor = handler.CreateActorStringPublic(theoryData.TokenDescriptor.Subject);
        }

        public static TheoryData<Saml2TheoryData> RoundTripActorTheoryData
        {
            get =>  new TheoryData<Saml2TheoryData>
            {
                new Saml2TheoryData
                {
                    First = true,
                    Handler = new Saml2SecurityTokenHandlerPublic(),
                    TestId = nameof(ClaimSets.DefaultClaimsIdentity),
                    TokenDescriptor = new SecurityTokenDescriptor
                    {
                        Subject = ClaimSets.DefaultClaimsIdentity
                    }
                }
            };
        }

        [Theory, MemberData(nameof(ValidateAudienceTheoryData))]
        public void ValidateAudience(Saml2TheoryData theoryData)
        {
            TestUtilities.WriteHeader($"{this}.ValidateAudience", theoryData);
            var context = new CompareContext($"{this}.ValidateAudience, {theoryData}");
            try
            {
                (theoryData.Handler as Saml2SecurityTokenHandlerPublic).ValidateAudiencePublic(theoryData.Audiences, null, theoryData.ValidationParameters);
                theoryData.ExpectedException.ProcessNoException(context);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<Saml2TheoryData> ValidateAudienceTheoryData
        {
            get
            {
                var tokenTheoryData = new List<TokenTheoryData>();
                var theoryData = new TheoryData<Saml2TheoryData>();

                ValidateTheoryData.AddValidateAudienceTheoryData(tokenTheoryData);
                foreach (var item in tokenTheoryData)
                    theoryData.Add(new Saml2TheoryData(item)
                    {
                        Handler = new Saml2SecurityTokenHandlerPublic()
                    });

                return theoryData;
            }
        }

        [Theory, MemberData(nameof(ValidateIssuerTheoryData))]
        public void ValidateIssuer(Saml2TheoryData theoryData)
        {
            TestUtilities.WriteHeader($"{this}.ValidateIssuer", theoryData);
            var context = new CompareContext($"{this}.ValidateAudience, {theoryData}");
            try
            {
                (theoryData.Handler as Saml2SecurityTokenHandlerPublic).ValidateIssuerPublic(theoryData.Issuer, null, theoryData.ValidationParameters);
                theoryData.ExpectedException.ProcessNoException(context);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<Saml2TheoryData> ValidateIssuerTheoryData
        {
            get
            {
                var tokenTheoryData = new List<TokenTheoryData>();
                ValidateTheoryData.AddValidateIssuerTheoryData(tokenTheoryData);

                var theoryData = new TheoryData<Saml2TheoryData>();
                foreach (var item in tokenTheoryData)
                    theoryData.Add(new Saml2TheoryData(item)
                    {
                        Handler = new Saml2SecurityTokenHandlerPublic()
                    });

                return theoryData;
            }
        }

        [Theory, MemberData(nameof(ValidateTokenTheoryData))]
        public void ValidateToken(Saml2TheoryData theoryData)
        {
            TestUtilities.WriteHeader($"{this}.ValidateToken", theoryData);
            var context = new CompareContext($"{this}.ValidateToken, {theoryData}");
            ClaimsPrincipal retVal = null;
            try
            {
                retVal = theoryData.Handler.ValidateToken(theoryData.Token, theoryData.ValidationParameters, out SecurityToken validatedToken);
                theoryData.ExpectedException.ProcessNoException(context);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<Saml2TheoryData> ValidateTokenTheoryData
        {
            get
            {
                // uncomment to view exception displayed to user
                // ExpectedException.DefaultVerbose = true;

                return new TheoryData<Saml2TheoryData>
                {
                    new Saml2TheoryData
                    {
                        Handler = new Saml2SecurityTokenHandler(),
                        TestId = nameof(ReferenceTokens.Saml2Token_Valid),
                        Token = ReferenceTokens.Saml2Token_Valid,
                        ValidationParameters = new TokenValidationParameters
                        {
                            IssuerSigningKey = KeyingMaterial.DefaultAADSigningKey,
                            ValidateIssuer = false,
                            ValidateAudience = false,
                            ValidateLifetime = false,
                        }
                    },
                    new Saml2TheoryData
                    {
                        ExpectedException = ExpectedException.ArgumentNullException("IDX10000:"),
                        First = true,
                        Handler = new Saml2SecurityTokenHandler(),
                        TestId = "Null-SecurityToken",
                        Token = null,
                        ValidationParameters = new TokenValidationParameters()
                    },
                    new Saml2TheoryData
                    {
                        ExpectedException = ExpectedException.ArgumentNullException("IDX10000:"),
                        Handler = new Saml2SecurityTokenHandler(),
                        TestId = "NULL-TokenValidationParameters",
                        Token = "s",
                        ValidationParameters = null,
                    },
                    new Saml2TheoryData
                    {
                        ExpectedException = ExpectedException.ArgumentException("IDX10209:"),
                        Handler = new Saml2SecurityTokenHandler { MaximumTokenSizeInBytes = 1 },
                        TestId = "SecurityTokenTooLarge",
                        Token = "ss",
                        ValidationParameters = new TokenValidationParameters(),
                    },
                    new Saml2TheoryData
                    {
                        ExpectedException = new ExpectedException(typeof(Saml2SecurityTokenReadException), "IDX13106:"),
                        Handler = new Saml2SecurityTokenHandler(),
                        TestId = nameof(ReferenceTokens.Saml2Token_MissingVersion),
                        Token = ReferenceTokens.Saml2Token_MissingVersion,
                        ValidationParameters = new TokenValidationParameters(),
                    },
                    new Saml2TheoryData
                    {
                        ExpectedException = new ExpectedException(typeof(Saml2SecurityTokenReadException), "IDX13137:"),
                        Handler = new Saml2SecurityTokenHandler(),
                        TestId = nameof(ReferenceTokens.Saml2Token_VersionNotV20),
                        Token = ReferenceTokens.Saml2Token_VersionNotV20,
                        ValidationParameters = new TokenValidationParameters(),
                    },
                    new Saml2TheoryData
                    {
                        ExpectedException = new ExpectedException(typeof(Saml2SecurityTokenReadException), "IDX13106:"),
                        Handler = new Saml2SecurityTokenHandler(),
                        TestId = nameof(ReferenceTokens.Saml2Token_IdMissing),
                        Token = ReferenceTokens.Saml2Token_IdMissing,
                        ValidationParameters = new TokenValidationParameters(),
                    },
                    new Saml2TheoryData
                    {
                        ExpectedException = new ExpectedException(typeof(Saml2SecurityTokenReadException), "IDX13106:"),
                        Handler = new Saml2SecurityTokenHandler(),
                        TestId = nameof(ReferenceTokens.Saml2Token_IssueInstantMissing),
                        Token = ReferenceTokens.Saml2Token_IssueInstantMissing,
                        ValidationParameters = new TokenValidationParameters(),
                    },
                    new Saml2TheoryData
                    {
                        ExpectedException = new ExpectedException(typeof(Saml2SecurityTokenReadException), "IDX13102:", typeof(FormatException)),
                        Handler = new Saml2SecurityTokenHandler(),
                        TestId = nameof(ReferenceTokens.Saml2Token_IssueInstantFormatError),
                        Token = ReferenceTokens.Saml2Token_IssueInstantFormatError,
                        ValidationParameters = new TokenValidationParameters(),
                    },
                    new Saml2TheoryData
                    {
                        ExpectedException = new ExpectedException(typeof(Saml2SecurityTokenReadException), "IDX13102:", typeof(XmlReadException)),
                        Handler = new Saml2SecurityTokenHandler(),
                        TestId = nameof(ReferenceTokens.Saml2Token_IssuerMissing),
                        Token = ReferenceTokens.Saml2Token_IssuerMissing,
                        ValidationParameters = new TokenValidationParameters(),
                    },
                    new Saml2TheoryData
                    {
                        ExpectedException = new ExpectedException(typeof(Saml2SecurityTokenReadException), "IDX13108:"),
                        Handler = new Saml2SecurityTokenHandler(),
                        TestId = nameof(ReferenceTokens.Saml2Token_NoSubjectNoStatements),
                        Token = ReferenceTokens.Saml2Token_NoSubjectNoStatements,
                        ValidationParameters = new TokenValidationParameters(),
                    },
                    new Saml2TheoryData
                    {
                        ExpectedException = new ExpectedException(typeof(Saml2SecurityTokenReadException), "IDX13138:"),
                        Handler = new Saml2SecurityTokenHandler(),
                        TestId = nameof(ReferenceTokens.Saml2Token_NoAttributes),
                        Token = ReferenceTokens.Saml2Token_NoAttributes,
                        ValidationParameters = new TokenValidationParameters(),
                    },
                    new Saml2TheoryData
                    {
                        Handler = new Saml2SecurityTokenHandler(),
                        TestId = $"{nameof(ReferenceTokens.Saml2Token_Valid)} IssuerSigningKey set",
                        Token = ReferenceTokens.Saml2Token_Valid,
                        ValidationParameters = new TokenValidationParameters
                        {
                            IssuerSigningKey = KeyingMaterial.DefaultAADSigningKey,
                            ValidateIssuer = false,
                            ValidateAudience = false,
                            ValidateLifetime = false,
                        }
                    },
                    new Saml2TheoryData
                    {
                        Handler = new Saml2SecurityTokenHandler(),
                        TestId = nameof(ReferenceTokens.Saml2Token_Valid_Spaces_Added),
                        Token = ReferenceTokens.Saml2Token_Valid_Spaces_Added,
                        ValidationParameters = new TokenValidationParameters
                        {
                            IssuerSigningKey = KeyingMaterial.DefaultAADSigningKey,
                            ValidateIssuer = false,
                            ValidateAudience = false,
                            ValidateLifetime = false,
                        }
                    },
                    new Saml2TheoryData
                    {
                        ExpectedException = ExpectedException.SecurityTokenInvalidSignatureException("IDX10503:"),
                        Handler = new Saml2SecurityTokenHandler(),
                        TestId = nameof(ReferenceTokens.Saml2Token_Formated),
                        Token = ReferenceTokens.Saml2Token_Formated,
                        ValidationParameters = new TokenValidationParameters
                        {
                            IssuerSigningKey = KeyingMaterial.DefaultAADSigningKey,
                        }
                    },
                    new Saml2TheoryData
                    {
                        Handler = new Saml2SecurityTokenHandler(),
                        TestId = $"{nameof(ReferenceTokens.Saml2Token_Valid)} IssuerSigningKey Rsa",
                        Token = ReferenceTokens.Saml2Token_Valid_WithRsaKeyValue,
                        ValidationParameters = new TokenValidationParameters
                        {
                            IssuerSigningKey = KeyingMaterial.DefaultRsaSecurityKey2,
                            ValidateIssuer = false,
                            ValidateAudience = false,
                            ValidateLifetime = false,
                        }
                    },
                    new Saml2TheoryData
                    {
                        Handler = new Saml2SecurityTokenHandler(),
                        TestId = $"{nameof(ReferenceTokens.Saml2Token_Valid)} IssuerSigningKey JsonWithCertificate",
                        Token = ReferenceTokens.Saml2Token_Valid,
                        ValidationParameters = new TokenValidationParameters
                        {
                            IssuerSigningKey = KeyingMaterial.DefaultJsonWebKeyWithCertificate2,
                            ValidateIssuer = false,
                            ValidateAudience = false,
                            ValidateLifetime = false,
                        }
                    },
                    new Saml2TheoryData
                    {
                        Handler = new Saml2SecurityTokenHandler(),
                        TestId = $"{nameof(ReferenceTokens.Saml2Token_Valid)} IssuerSigningKey JsonWithParameters",
                        Token = ReferenceTokens.Saml2Token_Valid,
                        ValidationParameters = new TokenValidationParameters
                        {
                            IssuerSigningKey = KeyingMaterial.DefaultJsonWebKeyWithParameters2,
                            ValidateIssuer = false,
                            ValidateAudience = false,
                            ValidateLifetime = false,
                        }
                    },
                    new Saml2TheoryData
                    {
                        ExpectedException = ExpectedException.SecurityTokenInvalidSignatureException("IDX10503:"),
                        Handler = new Saml2SecurityTokenHandler(),
                        TestId = nameof(ReferenceTokens.Saml2Token_AttributeTampered),
                        Token = ReferenceTokens.Saml2Token_AttributeTampered,
                        ValidationParameters = new TokenValidationParameters
                        {
                            IssuerSigningKey = KeyingMaterial.DefaultAADSigningKey,
                        }
                    },
                    new Saml2TheoryData
                    {
                        ExpectedException = ExpectedException.SecurityTokenInvalidSignatureException("IDX10503:"),
                        Handler = new Saml2SecurityTokenHandler(),
                        TestId = nameof(ReferenceTokens.Saml2Token_DigestTampered),
                        Token = ReferenceTokens.Saml2Token_DigestTampered,
                        ValidationParameters = new TokenValidationParameters
                        {
                            IssuerSigningKey = KeyingMaterial.DefaultAADSigningKey,
                        }
                    },
                    // Removed until we have a way of matching a SecurityKey with a KeyInfo.
                    new Saml2TheoryData
                    {
                        ExpectedException = ExpectedException.SecurityTokenSignatureKeyNotFoundException("IDX10501:"),
                        Handler = new Saml2SecurityTokenHandler(),
                        TestId = nameof(ReferenceTokens.Saml2Token_AttributeTampered_NoKeyMatch),
                        Token = ReferenceTokens.Saml2Token_AttributeTampered_NoKeyMatch,
                        ValidationParameters = new TokenValidationParameters
                        {
                            IssuerSigningKey = KeyingMaterial.DefaultAADSigningKey,
                        }
                    },
                    new Saml2TheoryData
                    {
                        ExpectedException = ExpectedException.SecurityTokenInvalidSignatureException("IDX10503:"),
                        Handler = new Saml2SecurityTokenHandler(),
                        TestId = nameof(ReferenceTokens.Saml2Token_SignatureTampered),
                        Token = ReferenceTokens.Saml2Token_SignatureTampered,
                        ValidationParameters = new TokenValidationParameters
                        {
                            IssuerSigningKey = KeyingMaterial.DefaultAADSigningKey,
                        }
                    },
                    new Saml2TheoryData
                    {
                        Handler = new Saml2SecurityTokenHandler(),
                        TestId = nameof(ReferenceTokens.Saml2Token_SignatureMissing),
                        Token = ReferenceTokens.Saml2Token_SignatureMissing,
                        ValidationParameters = new TokenValidationParameters
                        {
                            IssuerSigningKey = KeyingMaterial.DefaultAADSigningKey,
                            ValidateIssuer = false,
                            ValidateAudience = false,
                            ValidateLifetime = false,
                            RequireSignedTokens = false,
                        }
                    }
                };
            }
        }
    }

    public class Saml2SecurityTokenHandlerPublic : Saml2SecurityTokenHandler
    {
        public ICollection<Saml2Attribute> ConsolidateAttributesPublic(ICollection<Saml2Attribute> attributes)
        {
            return ConsolidateAttributes(attributes);
        }

        public string CreateActorStringPublic(ClaimsIdentity identity)
        {
            return CreateActorString(identity);
        }

        public void ProcessAttributeStatementPublic(Saml2AttributeStatement statement, ClaimsIdentity identity, string issuer)
        {
            ProcessAttributeStatement(statement, identity, issuer);
        }

        public string ValidateIssuerPublic(string issuer, SecurityToken token, TokenValidationParameters validationParameters)
        {
            return base.ValidateIssuer(issuer, token, validationParameters);
        }

        public void ValidateAudiencePublic(IEnumerable<string> audiences, SecurityToken token, TokenValidationParameters validationParameters)
        {
            base.ValidateAudience(audiences, token, validationParameters);
        }
    }

    public class Saml2SecurityTokenPublic : Saml2SecurityToken
    {
        public Saml2SecurityTokenPublic(Saml2Assertion assertion)
            : base(assertion)
        {
        }
    }

}

#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
