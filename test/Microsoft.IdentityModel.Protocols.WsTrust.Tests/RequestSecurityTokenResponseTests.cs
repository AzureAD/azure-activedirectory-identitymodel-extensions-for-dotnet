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
using System.IO;
using System.Text;
using System.Xml;
using Microsoft.IdentityModel.Protocols.WsSecurity;
using Microsoft.IdentityModel.TestUtils;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Tokens.Saml2;

using Xunit;

// Arrays as attribute arguments are not CLS-compliant
#pragma warning disable CS3016

namespace Microsoft.IdentityModel.Protocols.WsTrust.Tests
{
    public class RequestSecurityTokenResponseTests
    {
        [Theory, MemberData(nameof(ReadAndWriteResponseTheoryData))]
        public void ReadAndWriteResponse(WsTrustTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.ReadAndWriteResponse", theoryData);

            try
            {
                WsTrustResponse wsTrustResponse = null;
                using (var memoryStream = new MemoryStream())
                {
                    var writer = XmlDictionaryWriter.CreateTextWriter(memoryStream, Encoding.UTF8, false);
                    var serializer = new WsTrustSerializer();
                    serializer.WriteResponse(writer, theoryData.WsTrustVersion, theoryData.WsTrustResponse);
                    writer.Flush();

                    // sometimes it is helpful to see the xml that was generated.
                    // the next two lines are for this purpose.
                    var bytes = memoryStream.ToArray();
                    var xml = Encoding.UTF8.GetString(bytes);

                    var reader = XmlDictionaryReader.CreateTextReader(bytes, XmlDictionaryReaderQuotas.Max);
                    wsTrustResponse = serializer.ReadResponse(reader);
                    IdentityComparer.AreEqual(wsTrustResponse, theoryData.WsTrustResponse, context);
                }

                // indicates we want to validate the token
                if (theoryData.SecurityTokenHandler != null)
                {
                    var requestedSecurityToken = wsTrustResponse.RequestSecurityTokenResponseCollection[0].RequestedSecurityToken;
                    if (requestedSecurityToken.SecurityToken != null)
                    {
                        theoryData.SecurityTokenHandler.ValidateToken(theoryData.SecurityTokenHandler.WriteToken(requestedSecurityToken.SecurityToken), theoryData.TokenValidationParameters, out SecurityToken securityToken);
                    }
                    else if (requestedSecurityToken.TokenElement != null)
                    {
                        using (var memoryStream = new MemoryStream())
                        {
                            var writer = XmlDictionaryWriter.CreateTextWriter(memoryStream, Encoding.UTF8, false);
                            requestedSecurityToken.TokenElement.WriteTo(writer);
                            writer.Flush();
                            var tokenXml = Encoding.UTF8.GetString(memoryStream.ToArray());
                            theoryData.SecurityTokenHandler.ValidateToken(tokenXml, theoryData.TokenValidationParameters, out _);
                        }
                    }
                }

                theoryData.ExpectedException.ProcessNoException(context);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<WsTrustTheoryData> ReadAndWriteResponseTheoryData
        {
            get
            {
                var tokenHandler = new Saml2SecurityTokenHandler();
                var tokenDescriptor = Default.SecurityTokenDescriptor(Default.AsymmetricSigningCredentials);
                XmlElement xmlElement = CreateXmlElement(tokenHandler, tokenDescriptor);

                return new TheoryData<WsTrustTheoryData>
                {
                    new WsTrustTheoryData
                    {
                        First = true,
                        SecurityTokenHandler = new Saml2SecurityTokenHandler(),
                        TestId = "WsTrustResponseWithSaml2SecurityToken",
                        TokenValidationParameters = new TokenValidationParameters
                        {
                            IssuerSigningKey = Default.AsymmetricSigningCredentials.Key,
                            ValidateAudience = false,
                            ValidateIssuer = false,
                            ValidateLifetime = false
                        },
                        WsTrustResponse = new WsTrustResponse(new RequestSecurityTokenResponse
                        {
                            AppliesTo = WsDefaults.AppliesTo,
                            AttachedReference = WsDefaults.SecurityTokenReference,
                            Entropy = new Entropy(new BinarySecret(Guid.NewGuid().ToByteArray(), WsSecurityEncodingTypes.WsSecurity11.Base64)),
                            Lifetime = new Lifetime(DateTime.UtcNow, DateTime.UtcNow + TimeSpan.FromDays(1)),
                            KeyType = WsDefaults.KeyType,
                            RequestedProofToken = new RequestedProofToken(new BinarySecret(Guid.NewGuid().ToByteArray())),
                            RequestedSecurityToken = new RequestedSecurityToken(xmlElement),
                            TokenType = Saml2Constants.OasisWssSaml2TokenProfile11,
                            UnattachedReference = WsDefaults.SecurityTokenReference
                        }),
                        WsTrustVersion = WsTrustVersion.Trust13
                    }
                };
            }
        }

        private static XmlElement CreateXmlElement(SecurityTokenHandler tokenHandler, SecurityTokenDescriptor tokenDescriptor)
        {
            using (var memoryStream = new MemoryStream())
            {
                using (var xmlWriter = XmlDictionaryWriter.CreateTextWriter(memoryStream, Encoding.UTF8, false))
                {
                    tokenHandler.WriteToken(xmlWriter, tokenHandler.CreateToken(tokenDescriptor));
                    xmlWriter.Flush();
                }

                memoryStream.Seek(0, SeekOrigin.Begin);
                using (var xmlReader = XmlDictionaryReader.CreateTextReader(memoryStream, XmlDictionaryReaderQuotas.Max))
                    return WsTrustSerializer.CreateXmlElement(xmlReader);
            }
        }

        [Theory, MemberData(nameof(ReadRequestSeurityTokenResponseTheoryData))]
        public void ReadRequestSeurityTokenResponse(WsTrustTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.ReadRequestSeurityTokenResponse", theoryData);

            try
            {
                var requestSecurityTokenResponse = WsTrustSerializer.ReadRequestedSecurityToken(theoryData.Reader, theoryData.WsSerializationContext);
                theoryData.ExpectedException.ProcessNoException(context);
                IdentityComparer.AreEqual(requestSecurityTokenResponse, theoryData.RequestedSecurityToken, context);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<WsTrustTheoryData> ReadRequestSeurityTokenResponseTheoryData
        {
            get
            {
                var theoryData = new TheoryData<WsTrustTheoryData>
                {
                    new WsTrustTheoryData(ReferenceXml.RandomElementReader)
                    {
                        ExpectedException = ExpectedException.ArgumentNullException("serializationContext"),
                        First = true,
                        TestId = "SerializationContextNull",
                        WsSerializationContext = null
                    },
                    new WsTrustTheoryData(WsTrustVersion.Trust13)
                    {
                        ExpectedException = ExpectedException.ArgumentNullException("reader"),
                        Reader = null,
                        TestId = "ReaderNull",
                    },
                    new WsTrustTheoryData(WsTrustVersion.Trust13)
                    {
                        ExpectedException = ExpectedException.XmlReadException(),
                        Reader = ReferenceXml.RandomElementReader,
                        TestId = "ReaderNotOnCorrectElement",
                    }
                };

                return theoryData;
            }
        }

        [Theory, MemberData(nameof(ReadResponseTheoryData))]
        public void ReadResponse(WsTrustTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.ReadResponse", theoryData);

            try
            {
                var response = theoryData.WsTrustSerializer.ReadResponse(theoryData.Reader);
                theoryData.ExpectedException.ProcessNoException(context);
                IdentityComparer.AreEqual(response, theoryData.WsTrustRequest, context);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<WsTrustTheoryData> ReadResponseTheoryData
        {
            get
            {
                var theoryData = new TheoryData<WsTrustTheoryData>
                {
                    new WsTrustTheoryData(WsTrustVersion.Trust13)
                    {
                        ExpectedException = ExpectedException.ArgumentNullException("reader"),
                        First = true,
                        TestId = "ReaderNull",
                    }
                };

                XmlDictionaryReader reader = ReferenceXml.GetLifeTimeReader(WsTrustConstants.Trust13, DateTime.UtcNow, DateTime.UtcNow + TimeSpan.FromDays(1));
                reader.ReadStartElement();
                reader.ReadStartElement();
                theoryData.Add(new WsTrustTheoryData(WsTrustVersion.Trust13)
                {
                    ExpectedException = ExpectedException.XmlReadException("IDX30022:"),
                    Reader = reader,
                    TestId = "ReaderNotOnStartElement"
                });

                theoryData.Add(new WsTrustTheoryData(WsTrustVersion.Trust13)
                {
                    ExpectedException = ExpectedException.XmlReadException("IDX30024:"),
                    Reader = ReferenceXml.RandomElementReader,
                    TestId = "ReaderNotOnCorrectElement"
                });

                return theoryData;
            }
        }

        [Theory, MemberData(nameof(WriteResponseTheoryData))]
        public void WriteResponse(WsTrustTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.WriteResponse", theoryData);
            try
            {
                theoryData.WsTrustSerializer.WriteResponse(theoryData.Writer, theoryData.WsTrustVersion, theoryData.WsTrustResponse);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<WsTrustTheoryData> WriteResponseTheoryData
        {
            get
            {
                return new TheoryData<WsTrustTheoryData>
                {
                    new WsTrustTheoryData(new MemoryStream())
                    {
                        ExpectedException = ExpectedException.ArgumentNullException("wsTrustVersion"),
                        First = true,
                        TestId = "WsTrustVersionNull",
                        WsTrustResponse = new WsTrustResponse(),
                    },
                    new WsTrustTheoryData(WsTrustVersion.Trust13)
                    {
                        ExpectedException = ExpectedException.ArgumentNullException("writer"),
                        TestId = "WriterNull",
                        WsTrustResponse = new WsTrustResponse(),
                    },
                    new WsTrustTheoryData(new MemoryStream(), WsTrustVersion.Trust13)
                    {
                        ExpectedException = ExpectedException.ArgumentNullException("trustResponse"),
                        TestId = "WsTrustResponseNull"
                    }
                };
            }
        }

        [Theory, MemberData(nameof(WriteRequestSecurityTokenResponseTheoryData))]
        public void WriteRequestSecurityTokenResponse(WsTrustTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.WriteRequestSecurityTokenResponse", theoryData);
            try
            {
                theoryData.WsTrustSerializer.WriteRequestSecurityTokenResponse(theoryData.Writer, theoryData.WsTrustVersion, theoryData.RequestSecurityTokenResponse);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<WsTrustTheoryData> WriteRequestSecurityTokenResponseTheoryData
        {
            get
            {
                return new TheoryData<WsTrustTheoryData>
                {
                    new WsTrustTheoryData(new MemoryStream())
                    {
                        ExpectedException = ExpectedException.ArgumentNullException("wsTrustVersion"),
                        First = true,
                        TestId = "WsTrustVersionNull",
                        WsTrustResponse = new WsTrustResponse(),
                    },
                    new WsTrustTheoryData(WsTrustVersion.Trust13)
                    {
                        ExpectedException = ExpectedException.ArgumentNullException("writer"),
                        TestId = "WriterNull",
                        WsTrustResponse = new WsTrustResponse(),
                    },
                    new WsTrustTheoryData(new MemoryStream(), WsTrustVersion.Trust13)
                    {
                        ExpectedException = ExpectedException.ArgumentNullException("requestSecurityTokenResponse"),
                        TestId = "WsTrustResponseNull"
                    }
                };
            }
        }
    }
}

#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
