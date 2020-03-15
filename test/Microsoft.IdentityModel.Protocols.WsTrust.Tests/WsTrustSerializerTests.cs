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
using System.Xml;
using Microsoft.IdentityModel.TestUtils;
using Microsoft.IdentityModel.Xml;
using Xunit;

#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant

namespace Microsoft.IdentityModel.Protocols.WsTrust.Tests
{
    public class WsTrustSerializerTests
    {
        [Fact]
        public void Constructors()
        {
            TestUtilities.WriteHeader($"{this}.Constructors");
            CompareContext context = new CompareContext("Constructors");
            WsTrustSerializer wsTrustSerializer = new WsTrustSerializer();

            if (wsTrustSerializer.SecurityTokenHandlers.Count != 2)
                context.AddDiff("wsTrustSerializer.SecurityTokenHandlers.Count != 2");

            TestUtilities.AssertFailIfErrors(context);
        }

        [Theory, MemberData(nameof(ReadBinarySecrectTheoryData))]
        public void ReadBinarySecrect(WsTrustSerializerTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.ReadBinarySecrect", theoryData);
            try
            {
                var binarySecret = theoryData.WsTrustSerializer.ReadBinarySecrect(theoryData.Reader, theoryData.WsSerializationContext);
                IdentityComparer.AreEqual(binarySecret, theoryData.BinarySecret, context);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<WsTrustSerializerTheoryData> ReadBinarySecrectTheoryData
        {
            get
            {
                return new TheoryData<WsTrustSerializerTheoryData>
                {
                    new WsTrustSerializerTheoryData
                    {
                        ExpectedException = ExpectedException.ArgumentNullException("serializationContext"),
                        First = true,
                        TestId = "SerializationContextNull"
                    },
                    new WsTrustSerializerTheoryData
                    {
                        ExpectedException = ExpectedException.ArgumentNullException("reader"),
                        TestId = "ReaderNull",
                        WsSerializationContext = new WsSerializationContext(WsTrustVersion.Trust13)
                    },
                    new WsTrustSerializerTheoryData
                    {
                        BinarySecret = new BinarySecret(Convert.FromBase64String(KeyingMaterial.SelfSigned2048_SHA256), WsTrustConstants.TrustFeb2005.WsTrustBinarySecretTypes.AsymmetricKey),
                        Reader = ReferenceXml.GetBinarySecretReader(WsTrustConstants.TrustFeb2005, WsTrustConstants.TrustFeb2005.WsTrustBinarySecretTypes.AsymmetricKey, KeyingMaterial.SelfSigned2048_SHA256),
                        TestId = "TrustFeb2005",
                        WsSerializationContext = new WsSerializationContext(WsTrustVersion.TrustFeb2005)
                    },
                    new WsTrustSerializerTheoryData
                    {
                        BinarySecret = new BinarySecret(Convert.FromBase64String(KeyingMaterial.SelfSigned2048_SHA256), WsTrustConstants.Trust13.WsTrustBinarySecretTypes.AsymmetricKey),
                        Reader = ReferenceXml.GetBinarySecretReader(WsTrustConstants.Trust13, WsTrustConstants.Trust13.WsTrustBinarySecretTypes.AsymmetricKey, KeyingMaterial.SelfSigned2048_SHA256),
                        TestId = "Trust13",
                        WsSerializationContext = new WsSerializationContext(WsTrustVersion.Trust13)
                    },
                    new WsTrustSerializerTheoryData
                    {
                        BinarySecret = new BinarySecret(Convert.FromBase64String(KeyingMaterial.SelfSigned2048_SHA256), WsTrustConstants.Trust14.WsTrustBinarySecretTypes.AsymmetricKey),
                        Reader = ReferenceXml.GetBinarySecretReader(WsTrustConstants.Trust14, WsTrustConstants.Trust14.WsTrustBinarySecretTypes.AsymmetricKey, KeyingMaterial.SelfSigned2048_SHA256),
                        TestId = "Trust14",
                        WsSerializationContext = new WsSerializationContext(WsTrustVersion.Trust14)
                    },
                    new WsTrustSerializerTheoryData
                    {
                        ExpectedException = new ExpectedException(typeof(XmlReadException), "IDX30017:", typeof(System.Xml.XmlException)),
                        BinarySecret = new BinarySecret(Convert.FromBase64String(KeyingMaterial.SelfSigned2048_SHA256), WsTrustConstants.Trust13.WsTrustBinarySecretTypes.AsymmetricKey),
                        Reader = ReferenceXml.GetBinarySecretReader(WsTrustConstants.Trust13, WsTrustConstants.Trust13.WsTrustBinarySecretTypes.AsymmetricKey, "xxx"),
                        TestId = "EncodingError",
                        WsSerializationContext = new WsSerializationContext(WsTrustVersion.Trust13)
                    },
                    new WsTrustSerializerTheoryData
                    {
                        ExpectedException = new ExpectedException(typeof(XmlReadException), "IDX30011:"),
                        BinarySecret = new BinarySecret(Convert.FromBase64String(KeyingMaterial.SelfSigned2048_SHA256), WsTrustConstants.Trust13.WsTrustBinarySecretTypes.AsymmetricKey),
                        Reader = ReferenceXml.GetBinarySecretReader(WsTrustConstants.Trust13, WsTrustConstants.Trust13.WsTrustBinarySecretTypes.AsymmetricKey, KeyingMaterial.SelfSigned2048_SHA256),
                        TestId = "Trust13_14",
                        WsSerializationContext = new WsSerializationContext(WsTrustVersion.Trust14)
                    },
                };
            }
        }

        [Theory, MemberData(nameof(ReadLifetimeTheoryData))]
        public void ReadLifetime(WsTrustSerializerTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.ReadLifetime", theoryData);
            try
            {
                var lifetime = theoryData.WsTrustSerializer.ReadLifetime(theoryData.Reader, theoryData.WsSerializationContext);
                IdentityComparer.AreEqual(lifetime, theoryData.Lifetime, context);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<WsTrustSerializerTheoryData> ReadLifetimeTheoryData
        {
            get
            {
                DateTime createdDateTime = DateTime.UtcNow;
                DateTime expiresDateTime = createdDateTime + TimeSpan.FromDays(1);
                string created = XmlConvert.ToString(createdDateTime, XmlDateTimeSerializationMode.Utc);
                string expires = XmlConvert.ToString(expiresDateTime, XmlDateTimeSerializationMode.Utc);
                Lifetime lifetime = new Lifetime(createdDateTime, expiresDateTime);

                return new TheoryData<WsTrustSerializerTheoryData>
                {
                    new WsTrustSerializerTheoryData
                    {
                        ExpectedException = ExpectedException.ArgumentNullException("serializationContext"),
                        First = true,
                        TestId = "SerializationContextNull"
                    },
                    new WsTrustSerializerTheoryData
                    {
                        ExpectedException = ExpectedException.ArgumentNullException("reader"),
                        TestId = "ReaderNull",
                        WsSerializationContext = new WsSerializationContext(WsTrustVersion.Trust13)
                    },
                    new WsTrustSerializerTheoryData
                    {
                        Lifetime = new Lifetime(createdDateTime, expiresDateTime),
                        Reader = ReferenceXml.GetLifeTimeReader(WsTrustConstants.TrustFeb2005, created, expires),
                        TestId = "TrustFeb2005",
                        WsSerializationContext = new WsSerializationContext(WsTrustVersion.TrustFeb2005)
                    },
                    new WsTrustSerializerTheoryData
                    {
                        Lifetime = lifetime,
                        Reader = ReferenceXml.GetLifeTimeReader(WsTrustConstants.Trust13, created, expires),
                        TestId = "Trust13",
                        WsSerializationContext = new WsSerializationContext(WsTrustVersion.Trust13)
                    },
                    new WsTrustSerializerTheoryData
                    {
                        Lifetime = lifetime,
                        Reader = ReferenceXml.GetLifeTimeReader(WsTrustConstants.Trust14, created, expires),
                        TestId = "Trust14",
                        WsSerializationContext = new WsSerializationContext(WsTrustVersion.Trust14)
                    },
                    new WsTrustSerializerTheoryData
                    {
                        ExpectedException = new ExpectedException(typeof(XmlReadException), "IDX30011:"),
                        Lifetime = lifetime,
                        Reader = ReferenceXml.GetLifeTimeReader(WsTrustConstants.Trust14, created, expires),
                        TestId = "Trust14_13",
                        WsSerializationContext = new WsSerializationContext(WsTrustVersion.Trust13)
                    },
                    new WsTrustSerializerTheoryData
                    {
                        ExpectedException = new ExpectedException(typeof(XmlReadException), "IDX30017:", typeof(FormatException)),
                        Lifetime = lifetime,
                        Reader = ReferenceXml.GetLifeTimeReader(WsTrustConstants.Trust13, created, "xxx"),
                        TestId = "CreateParseError",
                        WsSerializationContext = new WsSerializationContext(WsTrustVersion.Trust13)
                    },
                    new WsTrustSerializerTheoryData
                    {
                        ExpectedException = new ExpectedException(typeof(XmlReadException), "IDX30017:", typeof(FormatException)),
                        Lifetime = lifetime,
                        Reader = ReferenceXml.GetLifeTimeReader(WsTrustConstants.Trust13, "xxx", expires),
                        TestId = "ExpireParseError",
                        WsSerializationContext = new WsSerializationContext(WsTrustVersion.Trust13)
                    }
                };
            }
        }

        [Theory, MemberData(nameof(ReadRequestTheoryData))]
        public void ReadRequest(WsTrustSerializerTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.ReadRequest", theoryData);

            try
            {
                var wsTrustRequest = theoryData.WsTrustSerializer.ReadRequest(theoryData.Reader);
                theoryData.ExpectedException.ProcessNoException(context);
                IdentityComparer.AreEqual(theoryData.WsTrustRequest, wsTrustRequest, context);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<WsTrustSerializerTheoryData> ReadRequestTheoryData
        {
            get
            {
                var theoryData = new TheoryData<WsTrustSerializerTheoryData>
                {
                    new WsTrustSerializerTheoryData
                    {
                        ExpectedException = ExpectedException.ArgumentNullException("reader"),
                        First = true,
                        TestId = "ReaderNull",
                    }
                };

                XmlDictionaryReader reader = ReferenceXml.GetWsRequestReader(WsTrustConstants.Trust13);
                reader.ReadStartElement();
                reader.ReadStartElement();
                theoryData.Add(new WsTrustSerializerTheoryData
                {
                    ExpectedException = ExpectedException.XmlReadException("IDX30022:"),
                    Reader = reader,
                    TestId = "ReaderNotOnStartElement"
                });

                theoryData.Add(new WsTrustSerializerTheoryData
                {
                    ExpectedException = ExpectedException.XmlReadException("IDX30024:"),
                    Reader = ReferenceXml.GetLifeTimeReader(WsTrustConstants.Trust13, XmlConvert.ToString(DateTime.UtcNow, XmlDateTimeSerializationMode.Utc), XmlConvert.ToString(DateTime.UtcNow + TimeSpan.FromDays(1), XmlDateTimeSerializationMode.Utc)),
                    TestId = "ReaderNotOnRequestSecurityToken"
                });


                return theoryData;
            }
        }

    }

    public class WsTrustSerializerTheoryData : TheoryDataBase
    {
        public BinarySecret BinarySecret { get; set; }

        public Lifetime Lifetime { get; set; }

        public WsSerializationContext WsSerializationContext { get; set; }

        public WsTrustRequest WsTrustRequest { get; set; }

        public WsTrustSerializer WsTrustSerializer { get; set; } = new WsTrustSerializer();

        public XmlDictionaryReader Reader { get; set; }
    }
}
