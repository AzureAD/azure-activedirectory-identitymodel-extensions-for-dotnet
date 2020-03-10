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

#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant

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
                var memeoryStream = new MemoryStream();
                var writer = XmlDictionaryWriter.CreateTextWriter(memeoryStream, Encoding.UTF8);
                var serializer = new WsTrustSerializer();
                serializer.WriteResponse(writer, theoryData.WsTrustVersion, theoryData.WsTrustResponse);
                writer.Flush();
                var bytes = memeoryStream.ToArray();
                var xml = Encoding.UTF8.GetString(bytes);
                var reader = XmlDictionaryReader.CreateTextReader(bytes, XmlDictionaryReaderQuotas.Max);
                var response = serializer.ReadResponse(reader);
                IdentityComparer.AreEqual(response, theoryData.WsTrustResponse, context);
                var validationParameters = new TokenValidationParameters
                {
                    IssuerSigningKey = Default.AsymmetricSigningCredentials.Key,
                    ValidateAudience = false,
                    ValidateIssuer = false,
                    ValidateLifetime = false
                };

                var tokenHandler = new Saml2SecurityTokenHandler();
                var token = response.RequestSecurityTokenResponseCollection[0].RequestedSecurityToken.SecurityToken as Saml2SecurityToken;
                var cp = tokenHandler.ValidateToken(token.Assertion.CanonicalString, validationParameters, out SecurityToken securityToken);
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
                var samlToken = tokenHandler.CreateToken(tokenDescriptor);
                var signedToken = tokenHandler.WriteToken(samlToken);
                var signedSamlToken = tokenHandler.ReadToken(signedToken);
                return new TheoryData<WsTrustTheoryData>
                {
                    new WsTrustTheoryData
                    {
                        First = true,
                        WsTrustResponse = new WsTrustResponse(new RequestSecurityTokenResponse
                        {
                            AppliesTo = WsDefaults.AppliesTo,
                            AttachedReference = WsDefaults.SecurityTokenReference,
                            Entropy = new Entropy(new BinarySecret(Guid.NewGuid().ToByteArray(), WsSecurity11EncodingTypes.Instance.Base64)),
                            Lifetime = new Lifetime(DateTime.UtcNow, DateTime.UtcNow + TimeSpan.FromDays(1)),
                            KeyType = WsDefaults.KeyType,
                            RequestedProofToken = new RequestedProofToken(new BinarySecret(Guid.NewGuid().ToByteArray())),
                            RequestedSecurityToken = new RequestedSecurityToken(signedSamlToken),
                            TokenType = Saml2Constants.OasisWssSaml2TokenProfile11,
                            UnattachedReference = WsDefaults.SecurityTokenReference
                        }),
                        TestId = "WsTrustResponseWithSaml2SecurityToken",
                        WsTrustVersion = WsTrustVersion.Trust13
                    }
                };
            }
        }

        [Theory, MemberData(nameof(ReadRequestSeurityTokenResponseTheoryData))]
        public void ReadRequestSeurityTokenResponse(WsTrustTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.ReadRequestSeurityTokenResponse", theoryData);

            try
            {
                var requestSecurityTokenResponse = theoryData.WsTrustSerializer.ReadRequestedSecurityToken(theoryData.Reader, theoryData.WsSerializationContext);
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
