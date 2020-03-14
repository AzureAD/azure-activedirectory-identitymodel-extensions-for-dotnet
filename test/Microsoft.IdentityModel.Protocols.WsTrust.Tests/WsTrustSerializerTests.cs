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
                        Reader = XmlUtilities.CreateDictionaryReader(ReferenceXml.GetBinarySecret(WsTrustConstants.TrustFeb2005.Prefix, WsTrustConstants.TrustFeb2005.Namespace, WsTrustConstants.TrustFeb2005.WsTrustBinarySecretTypes.AsymmetricKey, KeyingMaterial.SelfSigned2048_SHA256)),
                        TestId = "TrustFeb2005",
                        WsSerializationContext = new WsSerializationContext(WsTrustVersion.TrustFeb2005)
                    },
                    new WsTrustSerializerTheoryData
                    {
                        BinarySecret = new BinarySecret(Convert.FromBase64String(KeyingMaterial.SelfSigned2048_SHA256), WsTrustConstants.Trust13.WsTrustBinarySecretTypes.AsymmetricKey),
                        Reader = XmlUtilities.CreateDictionaryReader(ReferenceXml.GetBinarySecret(WsTrustConstants.Trust13.Prefix, WsTrustConstants.Trust13.Namespace, WsTrustConstants.Trust13.WsTrustBinarySecretTypes.AsymmetricKey, KeyingMaterial.SelfSigned2048_SHA256)),
                        TestId = "Trust13",
                        WsSerializationContext = new WsSerializationContext(WsTrustVersion.Trust13)
                    },
                    new WsTrustSerializerTheoryData
                    {
                        BinarySecret = new BinarySecret(Convert.FromBase64String(KeyingMaterial.SelfSigned2048_SHA256), WsTrustConstants.Trust14.WsTrustBinarySecretTypes.AsymmetricKey),
                        Reader = XmlUtilities.CreateDictionaryReader(ReferenceXml.GetBinarySecret(WsTrustConstants.Trust14.Prefix, WsTrustConstants.Trust14.Namespace, WsTrustConstants.Trust14.WsTrustBinarySecretTypes.AsymmetricKey, KeyingMaterial.SelfSigned2048_SHA256)),
                        TestId = "Trust14",
                        WsSerializationContext = new WsSerializationContext(WsTrustVersion.Trust14)
                    },
                    new WsTrustSerializerTheoryData
                    {
                        ExpectedException = new ExpectedException(typeof(XmlReadException), "IDX30017:", typeof(System.Xml.XmlException)),
                        BinarySecret = new BinarySecret(Convert.FromBase64String(KeyingMaterial.SelfSigned2048_SHA256), WsTrustConstants.Trust13.WsTrustBinarySecretTypes.AsymmetricKey),
                        Reader = XmlUtilities.CreateDictionaryReader(ReferenceXml.GetBinarySecret(WsTrustConstants.Trust13.Prefix, WsTrustConstants.Trust13.Namespace, WsTrustConstants.Trust13.WsTrustBinarySecretTypes.AsymmetricKey, "KeyingMaterial.SelfSigned2048_SHA256")),
                        TestId = "EncodingError",
                        WsSerializationContext = new WsSerializationContext(WsTrustVersion.Trust13)
                    },
                    new WsTrustSerializerTheoryData
                    {
                        ExpectedException = new ExpectedException(typeof(XmlReadException), "IDX30011:"),
                        BinarySecret = new BinarySecret(Convert.FromBase64String(KeyingMaterial.SelfSigned2048_SHA256), WsTrustConstants.Trust13.WsTrustBinarySecretTypes.AsymmetricKey),
                        Reader = XmlUtilities.CreateDictionaryReader(ReferenceXml.GetBinarySecret(WsTrustConstants.Trust13.Prefix, WsTrustConstants.Trust13.Namespace, WsTrustConstants.Trust13.WsTrustBinarySecretTypes.AsymmetricKey, KeyingMaterial.SelfSigned2048_SHA256)),
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
                        Lifetime = new Lifetime(XmlConvert.ToDateTime("2017-04-23T16:11:17.348Z", XmlDateTimeSerializationMode.Utc), XmlConvert.ToDateTime("2017-04-23T17:11:17.348Z", XmlDateTimeSerializationMode.Utc)),
                        Reader = XmlUtilities.CreateDictionaryReader(ReferenceXml.GetLifeTime(WsTrustConstants.TrustFeb2005.Prefix, WsTrustConstants.TrustFeb2005.Namespace, "2017-04-23T16:11:17.348Z", "2017-04-23T17:11:17.348Z")),
                        TestId = "TrustFeb2005",
                        WsSerializationContext = new WsSerializationContext(WsTrustVersion.TrustFeb2005)
                    },
                    new WsTrustSerializerTheoryData
                    {
                        Lifetime = new Lifetime(XmlConvert.ToDateTime("2017-04-23T16:11:17.348Z", XmlDateTimeSerializationMode.Utc), XmlConvert.ToDateTime("2017-04-23T17:11:17.348Z", XmlDateTimeSerializationMode.Utc)),
                        Reader = XmlUtilities.CreateDictionaryReader(ReferenceXml.GetLifeTime(WsTrustConstants.Trust13.Prefix, WsTrustConstants.Trust13.Namespace, "2017-04-23T16:11:17.348Z", "2017-04-23T17:11:17.348Z")),
                        TestId = "Trust13",
                        WsSerializationContext = new WsSerializationContext(WsTrustVersion.Trust13)
                    },
                    new WsTrustSerializerTheoryData
                    {
                        Lifetime = new Lifetime(XmlConvert.ToDateTime("2017-04-23T16:11:17.348Z", XmlDateTimeSerializationMode.Utc), XmlConvert.ToDateTime("2017-04-23T17:11:17.348Z", XmlDateTimeSerializationMode.Utc)),
                        Reader = XmlUtilities.CreateDictionaryReader(ReferenceXml.GetLifeTime(WsTrustConstants.Trust14.Prefix, WsTrustConstants.Trust14.Namespace, "2017-04-23T16:11:17.348Z", "2017-04-23T17:11:17.348Z")),
                        TestId = "Trust14",
                        WsSerializationContext = new WsSerializationContext(WsTrustVersion.Trust14)
                    },
                    new WsTrustSerializerTheoryData
                    {
                        ExpectedException = new ExpectedException(typeof(XmlReadException), "IDX30011:"),
                        Lifetime = new Lifetime(XmlConvert.ToDateTime("2017-04-23T16:11:17.348Z", XmlDateTimeSerializationMode.Utc), XmlConvert.ToDateTime("2017-04-23T17:11:17.348Z", XmlDateTimeSerializationMode.Utc)),
                        Reader = XmlUtilities.CreateDictionaryReader(ReferenceXml.GetLifeTime(WsTrustConstants.Trust14, "2017-04-23T16:11:17.348Z", "2017-04-23T17:11:17.348Z")),
                        TestId = "Trust14_13",
                        WsSerializationContext = new WsSerializationContext(WsTrustVersion.Trust13)
                    },
                    new WsTrustSerializerTheoryData
                    {
                        ExpectedException = new ExpectedException(typeof(XmlReadException), "IDX30017:", typeof(FormatException)),
                        Lifetime = new Lifetime(XmlConvert.ToDateTime("2017-04-23T16:11:17.348Z", XmlDateTimeSerializationMode.Utc), XmlConvert.ToDateTime("2017-04-23T17:11:17.348Z", XmlDateTimeSerializationMode.Utc)),
                        Reader = XmlUtilities.CreateDictionaryReader(ReferenceXml.GetLifeTime(WsTrustConstants.Trust13, "2017-04-23T16:11:17.348Z", "xxx")),
                        TestId = "ParseErrorCreate",
                        WsSerializationContext = new WsSerializationContext(WsTrustVersion.Trust13)
                    },
                    new WsTrustSerializerTheoryData
                    {
                        ExpectedException = new ExpectedException(typeof(XmlReadException), "IDX30017:", typeof(FormatException)),
                        Lifetime = new Lifetime(XmlConvert.ToDateTime("2017-04-23T16:11:17.348Z", XmlDateTimeSerializationMode.Utc), XmlConvert.ToDateTime("2017-04-23T17:11:17.348Z", XmlDateTimeSerializationMode.Utc)),
                        Reader = XmlUtilities.CreateDictionaryReader(ReferenceXml.GetLifeTime(WsTrustConstants.Trust13, "xxx", "2017-04-23T17:11:17.348Z")),
                        TestId = "ParseErrorExpire",
                        WsSerializationContext = new WsSerializationContext(WsTrustVersion.Trust13)
                    }
                };
            }
        }
    }

    public class WsTrustSerializerTheoryData : TheoryDataBase
    {
        public BinarySecret BinarySecret { get; set; }

        public Lifetime Lifetime { get; set; }

        public WsSerializationContext WsSerializationContext { get; set; }

        public WsTrustSerializer WsTrustSerializer { get; set; } = new WsTrustSerializer();

        public XmlDictionaryReader Reader { get; set; }
    }
}
