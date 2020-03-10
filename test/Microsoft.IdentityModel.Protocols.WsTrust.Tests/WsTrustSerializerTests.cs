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
using System.Text;
using System.Xml;
using Microsoft.IdentityModel.Protocols.WsFed;
using Microsoft.IdentityModel.Protocols.WsSecurity;
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
        public void ReadBinarySecrect(WsTrustTheoryData theoryData)
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

        public static TheoryData<WsTrustTheoryData> ReadBinarySecrectTheoryData
        {
            get
            {
                return new TheoryData<WsTrustTheoryData>
                {
                    new WsTrustTheoryData(ReferenceXml.RandomElementReader)
                    {
                        ExpectedException = ExpectedException.ArgumentNullException("serializationContext"),
                        First = true,
                        TestId = "SerializationContextNull"
                    },
                    new WsTrustTheoryData(WsTrustVersion.Trust13)
                    {
                        ExpectedException = ExpectedException.ArgumentNullException("reader"),
                        TestId = "ReaderNull",
                        WsSerializationContext = new WsSerializationContext(WsTrustVersion.Trust13)
                    },
                    new WsTrustTheoryData(WsTrustVersion.TrustFeb2005)
                    {
                        BinarySecret = new BinarySecret(Convert.FromBase64String(KeyingMaterial.SelfSigned2048_SHA256), WsTrustConstants.TrustFeb2005.WsTrustBinarySecretTypes.AsymmetricKey),
                        Reader = ReferenceXml.GetBinarySecretReader(WsTrustConstants.TrustFeb2005, WsTrustConstants.TrustFeb2005.WsTrustBinarySecretTypes.AsymmetricKey, KeyingMaterial.SelfSigned2048_SHA256),
                        TestId = "TrustFeb2005"
                    },
                    new WsTrustTheoryData(WsTrustVersion.Trust13)
                    {
                        BinarySecret = new BinarySecret(Convert.FromBase64String(KeyingMaterial.SelfSigned2048_SHA256), WsTrustConstants.Trust13.WsTrustBinarySecretTypes.AsymmetricKey),
                        Reader = ReferenceXml.GetBinarySecretReader(WsTrustConstants.Trust13, WsTrustConstants.Trust13.WsTrustBinarySecretTypes.AsymmetricKey, KeyingMaterial.SelfSigned2048_SHA256),
                        TestId = "Trust13"
                    },
                    new WsTrustTheoryData(WsTrustVersion.Trust14)
                    {
                        BinarySecret = new BinarySecret(Convert.FromBase64String(KeyingMaterial.SelfSigned2048_SHA256), WsTrustConstants.Trust14.WsTrustBinarySecretTypes.AsymmetricKey),
                        Reader = ReferenceXml.GetBinarySecretReader(WsTrustConstants.Trust14, WsTrustConstants.Trust14.WsTrustBinarySecretTypes.AsymmetricKey, KeyingMaterial.SelfSigned2048_SHA256),
                        TestId = "Trust14"
                    },
                    new WsTrustTheoryData(WsTrustVersion.Trust13)
                    {
                        ExpectedException = new ExpectedException(typeof(XmlReadException), "IDX30017:", typeof(System.Xml.XmlException)),
                        BinarySecret = new BinarySecret(Convert.FromBase64String(KeyingMaterial.SelfSigned2048_SHA256), WsTrustConstants.Trust13.WsTrustBinarySecretTypes.AsymmetricKey),
                        Reader = ReferenceXml.GetBinarySecretReader(WsTrustConstants.Trust13, WsTrustConstants.Trust13.WsTrustBinarySecretTypes.AsymmetricKey, "xxx"),
                        TestId = "EncodingError"
                    },
                    new WsTrustTheoryData(WsTrustVersion.Trust14)
                    {
                        ExpectedException = new ExpectedException(typeof(XmlReadException), "IDX30011:"),
                        BinarySecret = new BinarySecret(Convert.FromBase64String(KeyingMaterial.SelfSigned2048_SHA256), WsTrustConstants.Trust13.WsTrustBinarySecretTypes.AsymmetricKey),
                        Reader = ReferenceXml.GetBinarySecretReader(WsTrustConstants.Trust13, WsTrustConstants.Trust13.WsTrustBinarySecretTypes.AsymmetricKey, KeyingMaterial.SelfSigned2048_SHA256),
                        TestId = "Trust13_14"
                    },
                    new WsTrustTheoryData(WsTrustVersion.Trust13)
                    {
                        ExpectedException = ExpectedException.XmlReadException("IDX30011:"),
                        Reader = ReferenceXml.RandomElementReader,
                        TestId = "ReaderNotOnCorrectElement"
                    }
                };
            }
        }

        [Theory, MemberData(nameof(ReadClaimsTheoryData))]
        public void ReadClaims(WsTrustTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.ReadClaims", theoryData);

            try
            {
                var claims = theoryData.WsTrustSerializer.ReadClaims(theoryData.Reader, theoryData.WsSerializationContext);
                theoryData.ExpectedException.ProcessNoException(context);
                IdentityComparer.AreEqual(claims, theoryData.Claims, context);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<WsTrustTheoryData> ReadClaimsTheoryData
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

        [Theory, MemberData(nameof(ReadLifetimeTheoryData))]
        public void ReadLifetime(WsTrustTheoryData theoryData)
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

        public static TheoryData<WsTrustTheoryData> ReadLifetimeTheoryData
        {
            get
            {
                DateTime created = DateTime.UtcNow;
                DateTime expires = created + TimeSpan.FromDays(1);
                Lifetime lifetime = new Lifetime(created, expires);

                return new TheoryData<WsTrustTheoryData>
                {
                    new WsTrustTheoryData(ReferenceXml.RandomElementReader)
                    {
                        ExpectedException = ExpectedException.ArgumentNullException("serializationContext"),
                        First = true,
                        TestId = "SerializationContextNull"
                    },
                    new WsTrustTheoryData(WsTrustVersion.Trust13)
                    {
                        ExpectedException = ExpectedException.ArgumentNullException("reader"),
                        TestId = "ReaderNull"
                    },
                    new WsTrustTheoryData(WsTrustVersion.TrustFeb2005)
                    {
                        Lifetime = lifetime,
                        Reader = ReferenceXml.GetLifeTimeReader(WsTrustConstants.TrustFeb2005, created, expires),
                        TestId = "TrustFeb2005"
                    },
                    new WsTrustTheoryData(WsTrustVersion.Trust13)
                    {
                        Lifetime = lifetime,
                        Reader = ReferenceXml.GetLifeTimeReader(WsTrustConstants.Trust13, created, expires),
                        TestId = "Trust13"
                    },
                    new WsTrustTheoryData(WsTrustVersion.Trust14)
                    {
                        Lifetime = lifetime,
                        Reader = ReferenceXml.GetLifeTimeReader(WsTrustConstants.Trust14, created, expires),
                        TestId = "Trust14"
                    },
                    new WsTrustTheoryData(WsTrustVersion.Trust13)
                    {
                        ExpectedException = ExpectedException.XmlReadException("IDX30011:"),
                        Lifetime = lifetime,
                        Reader = ReferenceXml.GetLifeTimeReader(WsTrustConstants.Trust14, created, expires),
                        TestId = "Trust14_13"
                    },
                    new WsTrustTheoryData(WsTrustVersion.Trust13)
                    {
                        ExpectedException = ExpectedException.XmlReadException("IDX30017:", typeof(FormatException)),
                        Lifetime = lifetime,
                        Reader = ReferenceXml.GetLifeTimeReader(WsTrustConstants.Trust13, XmlConvert.ToString(created, XmlDateTimeSerializationMode.Utc), "xxx"),
                        TestId = "CreateParseError"
                    },
                    new WsTrustTheoryData(WsTrustVersion.Trust13)
                    {
                        ExpectedException = ExpectedException.XmlReadException("IDX30017:", typeof(FormatException)),
                        Lifetime = lifetime,
                        Reader = ReferenceXml.GetLifeTimeReader(WsTrustConstants.Trust13, "xxx", XmlConvert.ToString(expires, XmlDateTimeSerializationMode.Utc)),
                        TestId = "ExpireParseError"
                    },
                    new WsTrustTheoryData(WsTrustVersion.Trust13)
                    {
                        ExpectedException = ExpectedException.XmlReadException("IDX30011:"),
                        Lifetime = lifetime,
                        Reader = ReferenceXml.RandomElementReader,
                        TestId = "ReaderNotOnCorrectElement"
                    }
                };
            }
        }

        [Theory, MemberData(nameof(ReadOnBehalfOfTheoryData))]
        public void ReadOnBehalfOf(WsTrustTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.ReadOnBehalfOf", theoryData);

            try
            {
                var onBehalfOf = theoryData.WsTrustSerializer.ReadOnBehalfOf(theoryData.Reader, theoryData.WsSerializationContext);
                theoryData.ExpectedException.ProcessNoException(context);
                IdentityComparer.AreEqual(onBehalfOf, theoryData.OnBehalfOf, context);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<WsTrustTheoryData> ReadOnBehalfOfTheoryData
        {
            get
            {
                var theoryData = new TheoryData<WsTrustTheoryData>
                {
                    new WsTrustTheoryData(ReferenceXml.RandomElementReader)
                    {
                        ExpectedException = ExpectedException.ArgumentNullException("serializationContext"),
                        First = true,
                        Reader = ReferenceXml.GetRequestSecurityTokenReader(WsTrustConstants.Trust13, ReferenceXml.Saml2Valid),
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

        [Theory, MemberData(nameof(ReadRequestedAttachedReferenceTheoryData))]
        public void ReadRequestedAttachedReference(WsTrustTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.ReadRequestedAttachedReference", theoryData);

            try
            {
                var attachedReference = theoryData.WsTrustSerializer.ReadRequestedAttachedReference(theoryData.Reader, theoryData.WsSerializationContext);
                theoryData.ExpectedException.ProcessNoException(context);
                IdentityComparer.AreEqual(attachedReference, theoryData.Reference, context);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<WsTrustTheoryData> ReadRequestedAttachedReferenceTheoryData
        {
            get
            {
                var theoryData = new TheoryData<WsTrustTheoryData>
                {
                    new WsTrustTheoryData(ReferenceXml.RandomElementReader)
                    {
                        ExpectedException = ExpectedException.ArgumentNullException("serializationContext"),
                        First = true,
                        Reader = ReferenceXml.GetRequestSecurityTokenReader(WsTrustConstants.Trust13, ReferenceXml.Saml2Valid),
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

        [Theory, MemberData(nameof(ReadRequestedSecurityTokenTheoryData))]
        public void ReadRequestedSecurityToken(WsTrustTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.ReadRequestedSecurityToken", theoryData);

            try
            {
                var requestedSecurityToken = theoryData.WsTrustSerializer.ReadRequestedSecurityToken(theoryData.Reader, theoryData.WsSerializationContext);
                theoryData.ExpectedException.ProcessNoException(context);
                IdentityComparer.AreEqual(requestedSecurityToken, theoryData.RequestedSecurityToken, context);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<WsTrustTheoryData> ReadRequestedSecurityTokenTheoryData
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

        [Theory, MemberData(nameof(ReadUnattachedReferenceTheoryData))]
        public void ReadUnattachedReference(WsTrustTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.ReadUnattachedReference", theoryData);

            try
            {
                var unattachedReference = theoryData.WsTrustSerializer.ReadRequestedUnattachedReference(theoryData.Reader, theoryData.WsSerializationContext);
                theoryData.ExpectedException.ProcessNoException(context);
                IdentityComparer.AreEqual(unattachedReference, theoryData.Reference, context);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<WsTrustTheoryData> ReadUnattachedReferenceTheoryData
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

        [Theory, MemberData(nameof(WriteBinarySecrectTheoryData))]
        public void WriteBinarySecrect(WsTrustTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.WriteBinarySecrect", theoryData);
            try
            {
                theoryData.WsTrustSerializer.WriteBinarySecret(theoryData.Writer, theoryData.WsSerializationContext, theoryData.BinarySecret);
                //IdentityComparer.AreEqual(binarySecret, theoryData.BinarySecret, context);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<WsTrustTheoryData> WriteBinarySecrectTheoryData
        {
            get
            {
                return new TheoryData<WsTrustTheoryData>
                {
                    new WsTrustTheoryData(new MemoryStream())
                    {
                        BinarySecret = new BinarySecret(Convert.FromBase64String(KeyingMaterial.SelfSigned2048_SHA256), WsTrustConstants.Trust13.WsTrustBinarySecretTypes.AsymmetricKey),
                        ExpectedException = ExpectedException.ArgumentNullException("serializationContext"),
                        First = true,
                        TestId = "SerializationContextNull"
                    },
                    new WsTrustTheoryData(WsTrustVersion.Trust13)
                    {
                        BinarySecret = new BinarySecret(Convert.FromBase64String(KeyingMaterial.SelfSigned2048_SHA256), WsTrustConstants.Trust13.WsTrustBinarySecretTypes.AsymmetricKey),
                        ExpectedException = ExpectedException.ArgumentNullException("writer"),
                        TestId = "WriterNull",
                    },
                    new WsTrustTheoryData(new MemoryStream(), WsTrustVersion.Trust13)
                    {
                        ExpectedException = ExpectedException.ArgumentNullException("binarySecret"),
                        TestId = "BinarySecretNull"
                    },
                    //new WsTrustSerializerTheoryData(WsTrustVersion.Trust13)
                    //{
                    //    BinarySecret = new BinarySecret(Convert.FromBase64String(KeyingMaterial.SelfSigned2048_SHA256), WsTrustConstants.Trust13.WsTrustBinarySecretTypes.AsymmetricKey),
                    //    Reader = ReferenceXml.GetBinarySecretReader(WsTrustConstants.Trust13, WsTrustConstants.Trust13.WsTrustBinarySecretTypes.AsymmetricKey, KeyingMaterial.SelfSigned2048_SHA256),
                    //    TestId = "Trust13"
                    //},
                    //new WsTrustSerializerTheoryData(WsTrustVersion.Trust14)
                    //{
                    //    BinarySecret = new BinarySecret(Convert.FromBase64String(KeyingMaterial.SelfSigned2048_SHA256), WsTrustConstants.Trust14.WsTrustBinarySecretTypes.AsymmetricKey),
                    //    Reader = ReferenceXml.GetBinarySecretReader(WsTrustConstants.Trust14, WsTrustConstants.Trust14.WsTrustBinarySecretTypes.AsymmetricKey, KeyingMaterial.SelfSigned2048_SHA256),
                    //    TestId = "Trust14"
                    //},
                    //new WsTrustSerializerTheoryData(WsTrustVersion.Trust13)
                    //{
                    //    ExpectedException = new ExpectedException(typeof(XmlReadException), "IDX30017:", typeof(System.Xml.XmlException)),
                    //    BinarySecret = new BinarySecret(Convert.FromBase64String(KeyingMaterial.SelfSigned2048_SHA256), WsTrustConstants.Trust13.WsTrustBinarySecretTypes.AsymmetricKey),
                    //    Reader = ReferenceXml.GetBinarySecretReader(WsTrustConstants.Trust13, WsTrustConstants.Trust13.WsTrustBinarySecretTypes.AsymmetricKey, "xxx"),
                    //    TestId = "EncodingError"
                    //},
                    //new WsTrustSerializerTheoryData(WsTrustVersion.Trust14)
                    //{
                    //    ExpectedException = new ExpectedException(typeof(XmlReadException), "IDX30011:"),
                    //    BinarySecret = new BinarySecret(Convert.FromBase64String(KeyingMaterial.SelfSigned2048_SHA256), WsTrustConstants.Trust13.WsTrustBinarySecretTypes.AsymmetricKey),
                    //    Reader = ReferenceXml.GetBinarySecretReader(WsTrustConstants.Trust13, WsTrustConstants.Trust13.WsTrustBinarySecretTypes.AsymmetricKey, KeyingMaterial.SelfSigned2048_SHA256),
                    //    TestId = "Trust13_14"
                    //},
                    //new WsTrustSerializerTheoryData(WsTrustVersion.Trust13)
                    //{
                    //    ExpectedException = ExpectedException.XmlReadException("IDX30011:"),
                    //    Reader = ReferenceXml.RandomElementReader,
                    //    TestId = "ReaderNotOnCorrectElement"
                    //}
                };
            }
        }

        [Theory, MemberData(nameof(WriteClaimsTheoryData))]
        public void WriteClaims(WsTrustTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.WriteClaims", theoryData);
            try
            {
                theoryData.WsTrustSerializer.WriteClaims(theoryData.Writer, theoryData.WsSerializationContext, theoryData.Claims);
                //IdentityComparer.AreEqual(claims, theoryData.Claims, context);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<WsTrustTheoryData> WriteClaimsTheoryData
        {
            get
            {
                return new TheoryData<WsTrustTheoryData>
                {
                    new WsTrustTheoryData(new MemoryStream())
                    {
                        Claims = new Claims("http://ClaimsDialect", new List<ClaimType>()),
                        ExpectedException = ExpectedException.ArgumentNullException("serializationContext"),
                        First = true,
                        TestId = "SerializationContextNull"
                    },
                    new WsTrustTheoryData(WsTrustVersion.Trust13)
                    {
                        Claims = new Claims("http://ClaimsDialect", new List<ClaimType>()),
                        ExpectedException = ExpectedException.ArgumentNullException("writer"),
                        TestId = "WriterNull",
                    },
                    new WsTrustTheoryData(new MemoryStream(), WsTrustVersion.Trust13)
                    {
                        ExpectedException = ExpectedException.ArgumentNullException("claims"),
                        TestId = "ClaimsNull"
                    }
                };
            }
        }

        [Theory, MemberData(nameof(WriteLifetimeTheoryData))]
        public void WriteLifetime(WsTrustTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.WriteLifetime", theoryData);
            try
            {
                theoryData.WsTrustSerializer.WriteLifetime(theoryData.Writer, theoryData.WsSerializationContext, theoryData.Lifetime);
                //IdentityComparer.AreEqual(lifetime, theoryData.Lifetime, context);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<WsTrustTheoryData> WriteLifetimeTheoryData
        {
            get
            {
                DateTime created = DateTime.UtcNow;
                DateTime expires = created + TimeSpan.FromDays(1);
                Lifetime lifetime = new Lifetime(created, expires);

                return new TheoryData<WsTrustTheoryData>
                {
                    new WsTrustTheoryData(new MemoryStream())
                    {
                        Lifetime = lifetime,
                        ExpectedException = ExpectedException.ArgumentNullException("serializationContext"),
                        First = true,
                        TestId = "SerializationContextNull"
                    },
                    new WsTrustTheoryData(WsTrustVersion.Trust13)
                    {
                        Lifetime = lifetime,
                        ExpectedException = ExpectedException.ArgumentNullException("writer"),
                        TestId = "WriterNull",
                    },
                    new WsTrustTheoryData(new MemoryStream(), WsTrustVersion.Trust13)
                    {
                        ExpectedException = ExpectedException.ArgumentNullException("lifetime"),
                        TestId = "LifetimeNull"
                    }
                };
            }
        }

        [Theory, MemberData(nameof(WriteOnBehalfOfTheoryData))]
        public void WriteOnBehalfOf(WsTrustTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.WriteOnBehalfOf", theoryData);
            try
            {
                theoryData.WsTrustSerializer.WriteOnBehalfOf(theoryData.Writer, theoryData.WsSerializationContext, theoryData.OnBehalfOf);
                //IdentityComparer.AreEqual(lifetime, theoryData.Lifetime, context);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<WsTrustTheoryData> WriteOnBehalfOfTheoryData
        {
            get
            {
                return new TheoryData<WsTrustTheoryData>
                {
                    new WsTrustTheoryData(new MemoryStream())
                    {
                        ExpectedException = ExpectedException.ArgumentNullException("serializationContext"),
                        First = true,
                        OnBehalfOf = new SecurityTokenElement(new SecurityTokenReference()),
                        TestId = "SerializationContextNull"
                    },
                    new WsTrustTheoryData(WsTrustVersion.Trust13)
                    {
                        ExpectedException = ExpectedException.ArgumentNullException("writer"),
                        OnBehalfOf = new SecurityTokenElement(new SecurityTokenReference()),
                        TestId = "WriterNull",
                    },
                    new WsTrustTheoryData(new MemoryStream(), WsTrustVersion.Trust13)
                    {
                        ExpectedException = ExpectedException.ArgumentNullException("onBehalfOf"),
                        TestId = "OnBehalfOfNull"
                    }
                };
            }
        }

        [Theory, MemberData(nameof(WriteProofEncryptionTheoryData))]
        public void WriteProofEncryption(WsTrustTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.WriteProofEncryption", theoryData);
            try
            {
                theoryData.WsTrustSerializer.WriteProofEncryption(theoryData.Writer, theoryData.WsSerializationContext, theoryData.ProofEncryption);
                //IdentityComparer.AreEqual(lifetime, theoryData.Lifetime, context);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<WsTrustTheoryData> WriteProofEncryptionTheoryData
        {
            get
            {
                return new TheoryData<WsTrustTheoryData>
                {
                    new WsTrustTheoryData(new MemoryStream())
                    {
                        ExpectedException = ExpectedException.ArgumentNullException("serializationContext"),
                        First = true,
                        ProofEncryption = new SecurityTokenElement(new SecurityTokenReference()),
                        TestId = "SerializationContextNull"
                    },
                    new WsTrustTheoryData(WsTrustVersion.Trust13)
                    {
                        ExpectedException = ExpectedException.ArgumentNullException("writer"),
                        ProofEncryption = new SecurityTokenElement(new SecurityTokenReference()),
                        TestId = "WriterNull",
                    },
                    new WsTrustTheoryData(new MemoryStream(), WsTrustVersion.Trust13)
                    {
                        ExpectedException = ExpectedException.ArgumentNullException("proofEncryption"),
                        TestId = "ProofEncryptionNull"
                    }
                };
            }
        }

        [Theory, MemberData(nameof(WriteRequestedAttachedReferenceTheoryData))]
        public void WriteRequestedAttachedReference(WsTrustTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.WriteRequestedAttachedReference", theoryData);
            try
            {
                theoryData.WsTrustSerializer.WriteRequestedAttachedReference(theoryData.Writer, theoryData.WsSerializationContext, theoryData.RequestedAttachedReference);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<WsTrustTheoryData> WriteRequestedAttachedReferenceTheoryData
        {
            get
            {
                return new TheoryData<WsTrustTheoryData>
                {
                    new WsTrustTheoryData(new MemoryStream())
                    {
                        ExpectedException = ExpectedException.ArgumentNullException("serializationContext"),
                        First = true,
                        RequestedAttachedReference = new SecurityTokenReference(),
                        TestId = "SerializationContextNull"
                    },
                    new WsTrustTheoryData(WsTrustVersion.Trust13)
                    {
                        ExpectedException = ExpectedException.ArgumentNullException("writer"),
                        RequestedAttachedReference = new SecurityTokenReference(),
                        TestId = "WriterNull",
                    },
                    new WsTrustTheoryData(new MemoryStream(), WsTrustVersion.Trust13)
                    {
                        ExpectedException = ExpectedException.ArgumentNullException("securityTokenReference"),
                        TestId = "RequestedAttachedReferenceNull"
                    }
                };
            }
        }

        [Theory, MemberData(nameof(WriteRequestedSecurityTokenTheoryData))]
        public void WriteRequestedSecurityToken(WsTrustTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.WriteRequestedSecurityToken", theoryData);
            try
            {
                theoryData.WsTrustSerializer.WriteRequestedSecurityToken(theoryData.Writer, theoryData.WsSerializationContext, theoryData.RequestedSecurityToken);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<WsTrustTheoryData> WriteRequestedSecurityTokenTheoryData
        {
            get
            {
                return new TheoryData<WsTrustTheoryData>
                {
                    new WsTrustTheoryData(new MemoryStream())
                    {
                        ExpectedException = ExpectedException.ArgumentNullException("serializationContext"),
                        First = true,
                        RequestedSecurityToken = new RequestedSecurityToken(),
                        TestId = "SerializationContextNull"
                    },
                    new WsTrustTheoryData(WsTrustVersion.Trust13)
                    {
                        ExpectedException = ExpectedException.ArgumentNullException("writer"),
                        RequestedSecurityToken = new RequestedSecurityToken(),
                        TestId = "WriterNull",
                    },
                    new WsTrustTheoryData(new MemoryStream(), WsTrustVersion.Trust13)
                    {
                        ExpectedException = ExpectedException.ArgumentNullException("requestedSecurityToken"),
                        TestId = "RequestedSecurityTokenNull"
                    }
                };
            }
        }

        [Theory, MemberData(nameof(WriteRequestedUnattachedReferenceTheoryData))]
        public void WriteRequestedUnattachedReference(WsTrustTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.WriteRequestedUnattachedReference", theoryData);
            try
            {
                theoryData.WsTrustSerializer.WriteRequestedUnattachedReference(theoryData.Writer, theoryData.WsSerializationContext, theoryData.RequestedUnattachedReference);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<WsTrustTheoryData> WriteRequestedUnattachedReferenceTheoryData
        {
            get
            {
                return new TheoryData<WsTrustTheoryData>
                {
                    new WsTrustTheoryData(new MemoryStream())
                    {
                        ExpectedException = ExpectedException.ArgumentNullException("serializationContext"),
                        First = true,
                        RequestedAttachedReference = new SecurityTokenReference(),
                        TestId = "SerializationContextNull"
                    },
                    new WsTrustTheoryData(WsTrustVersion.Trust13)
                    {
                        ExpectedException = ExpectedException.ArgumentNullException("writer"),
                        RequestedAttachedReference = new SecurityTokenReference(),
                        TestId = "WriterNull",
                    },
                    new WsTrustTheoryData(new MemoryStream(), WsTrustVersion.Trust13)
                    {
                        ExpectedException = ExpectedException.ArgumentNullException("securityTokenReference"),
                        TestId = "RequestedUnattachedReferenceNull"
                    }
                };
            }
        }

        [Fact]
        public void StringIntern()
        {
            TestUtilities.WriteHeader($"{this}.StringIntern");
            var context = new CompareContext("StringIntern");

            // WsTrustActions
            CheckRefs(context, "WsTrustFeb2005Actions.Cancel", (new WsTrustFeb2005Actions()).Cancel, WsTrustActions.TrustFeb2005.Cancel, WsTrustFeb2005Actions.Instance.Cancel);
            CheckRefs(context, "WsTrust13Actions.Cancel", (new WsTrust13Actions()).Cancel, WsTrustActions.Trust13.Cancel, WsTrust13Actions.Instance.Cancel);
            CheckRefs(context, "WsTrust14Actions.Cancel", (new WsTrust14Actions()).Cancel, WsTrustActions.Trust14.Cancel, WsTrust14Actions.Instance.Cancel);

            CheckRefs(context, "WsTrustFeb2005Actions.Issue", (new WsTrustFeb2005Actions()).Issue, WsTrustActions.TrustFeb2005.Issue, WsTrustFeb2005Actions.Instance.Issue);
            CheckRefs(context, "WsTrust13Actions.Issue", (new WsTrust13Actions()).Issue, WsTrustActions.Trust13.Issue, WsTrust13Actions.Instance.Issue);
            CheckRefs(context, "WsTrust14Actions.Issue", (new WsTrust14Actions()).Issue, WsTrustActions.Trust14.Issue, WsTrust14Actions.Instance.Issue);

            CheckRefs(context, "WsTrustFeb2005Actions.Validate", (new WsTrustFeb2005Actions()).Validate, WsTrustActions.TrustFeb2005.Validate, WsTrustFeb2005Actions.Instance.Validate);
            CheckRefs(context, "WsTrust13Actions.Validate", (new WsTrust13Actions()).Validate, WsTrustActions.Trust13.Validate, WsTrust13Actions.Instance.Validate);
            CheckRefs(context, "WsTrust14Actions.Validate", (new WsTrust14Actions()).Validate, WsTrustActions.Trust14.Validate, WsTrust14Actions.Instance.Validate);

            TestUtilities.AssertFailIfErrors(context);
        }

        private void CheckRefs(CompareContext context, string title, string string1, string string2, string string3)
        {
            if (!object.ReferenceEquals(string1, string2))
                context.AddDiff($"{title} : !object.ReferenceEquals(string1, string2)");

            if (!object.ReferenceEquals(string1, string3))
                context.AddDiff($"{title} : !object.ReferenceEquals(string1, string3)");

            if (!object.ReferenceEquals(string2, string3))
                context.AddDiff($"{title} : !object.ReferenceEquals(string2, string3)");
        }

    }
}
