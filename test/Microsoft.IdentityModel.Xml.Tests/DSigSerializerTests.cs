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
using System.Security.Cryptography;
using System.Text;
using System.Xml;
using Microsoft.IdentityModel.Tests;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Xml;
using Xunit;

#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant

namespace Microsoft.IdentityModel.Xml.Tests
{
    public class DSigSerializerTests
    {
        [Fact]
        public void GetSets()
        {
            var dsigSerializer = new DSigSerializer();
            TestUtilities.SetGet(dsigSerializer, "PreferredPrefix", (object)null, ExpectedException.ArgumentNullException("value"));

            dsigSerializer = new DSigSerializer();
            var context = new GetSetContext
            {
                PropertyNamesAndSetGetValue = new List<KeyValuePair<string, List<object>>>
                {
                    new KeyValuePair<string, List<object>>("PreferredPrefix", new List<object>{XmlSignatureConstants.PreferredPrefix, Guid.NewGuid().ToString(), Guid.NewGuid().ToString()}),
                },
                Object = dsigSerializer
            };

            TestUtilities.GetSet(context);
            TestUtilities.AssertFailIfErrors("DSigSerializerTests_GetSets", context.Errors);
        }

        [Theory, MemberData(nameof(ReadKeyInfoTheoryData))]
        public void ReadKeyInfo(DSigSerializerTheoryData theoryData)
        {
            TestUtilities.WriteHeader($"{this}.ReadKeyInfo", theoryData);
            var context = new CompareContext($"{this}.ReadKeyInfo, {theoryData.TestId}");
            try
            {
                var keyInfo = theoryData.Serializer.ReadKeyInfo(XmlUtilities.CreateDictionaryReader(theoryData.Xml));
                theoryData.ExpectedException.ProcessNoException(context.Diffs);
                IdentityComparer.AreKeyInfosEqual(keyInfo, theoryData.KeyInfo, context);

                // make sure we write and then read
                // as we only support partial elements, the KeyInfo's cannot be compared
                var ms = new MemoryStream();
                var writer = XmlDictionaryWriter.CreateTextWriter(ms);
                theoryData.Serializer.WriteKeyInfo(writer, keyInfo);
                writer.Flush();
                var xml = Encoding.UTF8.GetString(ms.ToArray());
                theoryData.Serializer.ReadKeyInfo(XmlUtilities.CreateDictionaryReader(xml));
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context.Diffs);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<DSigSerializerTheoryData> ReadKeyInfoTheoryData
        {
            get
            {
                // uncomment to view exception displayed to user
                // ExpectedException.DefaultVerbose = true;
                return new TheoryData<DSigSerializerTheoryData>
                {
                    //KeyInfoTest(KeyInfoTestSet.MalformedCertificate, new ExpectedException(typeof(XmlReadException), "IDX30017:", typeof(FormatException)), true),
                    KeyInfoTest(KeyInfoTestSet.KeyInfoFullyPopulated),
                    KeyInfoTest(KeyInfoTestSet.MultipleCertificates), 
                    KeyInfoTest(KeyInfoTestSet.MultipleIssuerSerial, new ExpectedException(typeof(XmlReadException), "IDX30015:")),
                    KeyInfoTest(KeyInfoTestSet.MultipleSKI, new ExpectedException(typeof(XmlReadException), "IDX30015:")),
                    KeyInfoTest(KeyInfoTestSet.MultipleSubjectName, new ExpectedException(typeof(XmlReadException), "IDX30015:")),
                    KeyInfoTest(KeyInfoTestSet.MultipleX509Data),
                    KeyInfoTest(KeyInfoTestSet.SingleCertificate),
                    KeyInfoTest(KeyInfoTestSet.SingleIssuerSerial),
                    KeyInfoTest(KeyInfoTestSet.SingleSKI),
                    KeyInfoTest(KeyInfoTestSet.SingleSubjectName),
                    KeyInfoTest(KeyInfoTestSet.WithRSAKeyValue),
                    KeyInfoTest(KeyInfoTestSet.WithWhitespace),
                    KeyInfoTest(KeyInfoTestSet.WithUnknownX509DataElements),
                    KeyInfoTest(KeyInfoTestSet.WithAllElements),
                    KeyInfoTest(KeyInfoTestSet.WithUnknownElements),
                    KeyInfoTest(KeyInfoTestSet.WrongNamespace, new ExpectedException(typeof(XmlReadException), "IDX30011:")),
                    KeyInfoTest(KeyInfoTestSet.KeyInfoEmpty),
                    KeyInfoTest(KeyInfoTestSet.X509DataEmpty, new ExpectedException(typeof(XmlReadException), "IDX30108")),
                    KeyInfoTest(KeyInfoTestSet.IssuerSerialEmpty, new ExpectedException(typeof(XmlReadException), "IDX30011:")),
                    KeyInfoTest(KeyInfoTestSet.RSAKeyValueEmpty, new ExpectedException(typeof(XmlReadException), "IDX30011:"))

                };
            }
        }

        [Theory, MemberData(nameof(WriteKeyInfoTheoryData))]
        public void WriteKeyInfo(DSigSerializerTheoryData theoryData)
        {
            TestUtilities.WriteHeader($"{this}.WriteKeyInfo", theoryData);
            var context = new CompareContext($"{this}.WriteKeyInfo, {theoryData.TestId}");
            try
            {
                var keyInfo = theoryData.Serializer.ReadKeyInfo(XmlUtilities.CreateDictionaryReader(theoryData.Xml));
                theoryData.ExpectedException.ProcessNoException(context.Diffs);
                IdentityComparer.AreKeyInfosEqual(keyInfo, theoryData.KeyInfo, context);
                var ms = new MemoryStream();
                var writer = XmlDictionaryWriter.CreateTextWriter(ms);
                theoryData.Serializer.WriteKeyInfo(writer, keyInfo);
                writer.Flush();
                var xml = Encoding.UTF8.GetString(ms.ToArray());
                IdentityComparer.AreEqual(theoryData.Xml, xml);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context.Diffs);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<DSigSerializerTheoryData> WriteKeyInfoTheoryData
        {
            get
            {
                return new TheoryData<DSigSerializerTheoryData>
                {
                    KeyInfoTest(KeyInfoTestSet.KeyInfoFullyPopulated),
                };
            }
        }

        public static DSigSerializerTheoryData KeyInfoTest(KeyInfoTestSet keyInfo, ExpectedException expectedException = null, bool first = false)
        {
            return new DSigSerializerTheoryData
            {
                ExpectedException = expectedException ?? ExpectedException.NoExceptionExpected,
                First = first,
                KeyInfo = keyInfo.KeyInfo,
                TestId = keyInfo.TestId ?? nameof(keyInfo),
                Xml = keyInfo.Xml,
            };
        }

        [Theory, MemberData(nameof(ReadSignatureTheoryData))]
        public void ReadSignature(DSigSerializerTheoryData theoryData)
        {
            TestUtilities.WriteHeader($"{this}.ReadSignature", theoryData);
            var context = new CompareContext($"{this}.ReadSignature, {theoryData.TestId}");
            try
            {
                var signature = theoryData.Serializer.ReadSignature(XmlUtilities.CreateDictionaryReader(theoryData.Xml));
                theoryData.ExpectedException.ProcessNoException(context);
                IdentityComparer.AreEqual(signature, theoryData.Signature, context);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<DSigSerializerTheoryData> ReadSignatureTheoryData
        {
            get
            {
                // uncomment to view exception displayed to user
                // ExpectedException.DefaultVerbose = true;
                return new TheoryData<DSigSerializerTheoryData>
                {
                    SignatureTest(SignatureTestSet.DefaultSignature, null, true),
                    SignatureTest(SignatureTestSet.UnknownDigestAlgorithm),
                    SignatureTest(SignatureTestSet.UnknownSignatureAlgorithm),
                    SignatureTest(SignatureTestSet.EmptySignature,
                    new ExpectedException(typeof(XmlReadException), "IDX30022:")),
                };
            }
        }

        [Theory, MemberData(nameof(WriteSignatureTheoryData))]
        public void WriteSignature(DSigSerializerTheoryData theoryData)
        {
            TestUtilities.WriteHeader($"{this}.WriteSignature", theoryData);
            var context = new CompareContext($"{this}.WriteSignature, {theoryData.TestId}");
            try
            {
                var signature = theoryData.Serializer.ReadSignature(XmlUtilities.CreateDictionaryReader(theoryData.Xml));
                theoryData.ExpectedException.ProcessNoException(context.Diffs);
                IdentityComparer.AreEqual(signature, theoryData.Signature, context);
                var ms = new MemoryStream();
                var writer = XmlDictionaryWriter.CreateTextWriter(ms);
                theoryData.Serializer.WriteSignature(writer, signature);
                writer.Flush();
                var xml = Encoding.UTF8.GetString(ms.ToArray());
                IdentityComparer.AreEqual(theoryData.Xml, xml);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<DSigSerializerTheoryData> WriteSignatureTheoryData
        {
            get
            {
                // uncomment to view exception displayed to user
                // ExpectedException.DefaultVerbose = true;

                return new TheoryData<DSigSerializerTheoryData>
                {
                    SignatureTest(SignatureTestSet.SignatureFullyPopulated)
                };
            }
        }

        public static DSigSerializerTheoryData SignatureTest(SignatureTestSet testSet, ExpectedException expectedException = null, bool first = false)
        {
            return new DSigSerializerTheoryData
            {
                ExpectedException = expectedException ?? ExpectedException.NoExceptionExpected,
                First = first,
                Signature = testSet.Signature,
                TestId = testSet.TestId ?? nameof(testSet),
                Xml = testSet.Xml,
            };
        }

        [Theory, MemberData(nameof(ReadSignedInfoTheoryData))]
        public void ReadSignedInfo(DSigSerializerTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.SignedInfoReadFrom", theoryData);
            try
            {
                var signedInfo = theoryData.Serializer.ReadSignedInfo(XmlUtilities.CreateDictionaryReader(theoryData.Xml));
                theoryData.ExpectedException.ProcessNoException(context);
                IdentityComparer.AreSignedInfosEqual(signedInfo, theoryData.SignedInfo, context);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<DSigSerializerTheoryData> ReadSignedInfoTheoryData
        {
            get
            {
                // uncomment to view exception displayed to user
                ExpectedException.DefaultVerbose = true;

                return new TheoryData<DSigSerializerTheoryData>
                {
                    SignedInfoTest(SignedInfoTestSet.CanonicalizationMethodMissing,
                        new ExpectedException(typeof(XmlReadException), "IDX30011:"), true),
                    SignedInfoTest(SignedInfoTestSet.MissingDigestMethod,
                        new ExpectedException(typeof(XmlReadException), "IDX30011: Unable to read XML. Expecting XmlReader to be at ns.element: 'http://www.w3.org/2000/09/xmldsig#.DigestMethod'")),
                    SignedInfoTest(SignedInfoTestSet.MissingDigestValue,
                        new ExpectedException(typeof(XmlReadException), "IDX30011: Unable to read XML. Expecting XmlReader to be at ns.element: 'http://www.w3.org/2000/09/xmldsig#.DigestValue'")),
                    SignedInfoTest(SignedInfoTestSet.NoTransforms),
                    SignedInfoTest(SignedInfoTestSet.StartsWithWhiteSpace),
                    SignedInfoTest(SignedInfoTestSet.TransformsMissing),
                    SignedInfoTest(SignedInfoTestSet.TwoReferences,
                        new ExpectedException(typeof(XmlReadException), "IDX30020: Unable to read XML. A second <Reference> element was found")),
                    SignedInfoTest(SignedInfoTestSet.ReferenceMissing,
                        new ExpectedException(typeof(XmlReadException), "IDX30011: Unable to read XML. Expecting XmlReader to be at ns.element: 'http://www.w3.org/2000/09/xmldsig#.Reference'")),
                    SignedInfoTest(SignedInfoTestSet.ReferenceDigestValueNotBase64),
                    SignedInfoTest(SignedInfoTestSet.UnknownReferenceTransform,
                        new ExpectedException(typeof(XmlReadException), "IDX14210:")),
                    SignedInfoTest(SignedInfoTestSet.Valid),
                    SignedInfoTest(SignedInfoTestSet.SignedInfoEmpty,
                        new ExpectedException(typeof(XmlReadException), "IDX30022:"))
                };
            }
        }

        [Theory, MemberData(nameof(WriteSignedInfoTheoryData))]
        public void WriteSignedInfo(DSigSerializerTheoryData theoryData)
        {
            TestUtilities.WriteHeader($"{this}.WriteSignedInfo", theoryData);
            var context = new CompareContext($"{this}.WriteSignedInfo, {theoryData.TestId}");
            try
            {
                var signedInfo = theoryData.Serializer.ReadSignedInfo(XmlUtilities.CreateDictionaryReader(theoryData.Xml));
                theoryData.ExpectedException.ProcessNoException(context.Diffs);
                IdentityComparer.AreEqual(signedInfo, theoryData.SignedInfo, context);
                var ms = new MemoryStream();
                var writer = XmlDictionaryWriter.CreateTextWriter(ms);
                theoryData.Serializer.WriteSignedInfo(writer, signedInfo);
                writer.Flush();
                var xml = Encoding.UTF8.GetString(ms.ToArray());
                IdentityComparer.AreEqual(theoryData.Xml, xml);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context.Diffs);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<DSigSerializerTheoryData> WriteSignedInfoTheoryData
        {
            get
            {
                // uncomment to view exception displayed to user
                // ExpectedException.DefaultVerbose = true;

                return new TheoryData<DSigSerializerTheoryData>
                { 
                    SignedInfoTest(SignedInfoTestSet.SignedInfoFullyPopulated)
                };
            }
        }

        public static DSigSerializerTheoryData SignedInfoTest(SignedInfoTestSet testSet, ExpectedException expectedException = null, bool first = false)
        {
            return new DSigSerializerTheoryData
            {
                ExpectedException = expectedException ?? ExpectedException.NoExceptionExpected,
                First = first,
                SignedInfo = testSet.SignedInfo,
                TestId = testSet.TestId ?? nameof(testSet),
                Xml = testSet.Xml,
            };
        }

        [Theory, MemberData(nameof(ReadReferenceTheoryData))]
        public void ReadReference(DSigSerializerTheoryData theoryData)
        {
            TestUtilities.WriteHeader($"{this}.ReadReference", theoryData);
            var context = new CompareContext($"{this}.ReadReference, {theoryData.TestId}");
            try
            {
                var reference = theoryData.Serializer.ReadReference(XmlUtilities.CreateDictionaryReader(theoryData.Xml));
                theoryData.ExpectedException.ProcessNoException(context);
                IdentityComparer.AreEqual(reference, theoryData.Reference, context);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<DSigSerializerTheoryData> ReadReferenceTheoryData
        {
            get
            {
                // uncomment to view exception displayed to user
                //ExpectedException.DefaultVerbose = true;

                return new TheoryData<DSigSerializerTheoryData>
                {
                    ReferenceTest(ReferenceTestSet.ReferenceEmpty,
                    new ExpectedException(typeof(XmlReadException), "IDX30022:"))
                };
            }
        }

        public static DSigSerializerTheoryData ReferenceTest(ReferenceTestSet testSet, ExpectedException expectedException = null, bool first = false)
        {
            return new DSigSerializerTheoryData
            {
                ExpectedException = expectedException ?? ExpectedException.NoExceptionExpected,
                First = first,
                Reference = testSet.Reference,
                TestId = testSet.TestId ?? nameof(testSet),
                Xml = testSet.Xml,
            };
        }

        [Theory, MemberData(nameof(ReadTransformTheoryData))]
        public void ReadTransform(DSigSerializerTheoryData theoryData)
        {
            TestUtilities.WriteHeader($"{this}.ReadTransform", theoryData);
            var context = new CompareContext($"{this}.ReadTransform, {theoryData.TestId}");
            try
            {
                var transform = theoryData.Serializer.ReadTransform(XmlUtilities.CreateDictionaryReader(theoryData.Xml));
                theoryData.ExpectedException.ProcessNoException(context);
                IdentityComparer.AreEqual(transform, theoryData.Transform, context);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context.Diffs);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<DSigSerializerTheoryData> ReadTransformTheoryData
        {
            get
            {
                // uncomment to view exception displayed to user
                // ExpectedException.DefaultVerbose = true;

                return new TheoryData<DSigSerializerTheoryData>
                {
                    TransformTest(TransformTestSet.AlgorithmDefaultReferenceUri, null, true),
                    TransformTest(TransformTestSet.Enveloped_AlgorithmMissing, new ExpectedException(typeof(XmlReadException), "IDX30105:")),
                    TransformTest(TransformTestSet.AlgorithmNull, new ExpectedException(typeof(XmlReadException), "IDX30105:")),
                    TransformTest(TransformTestSet.Enveloped_Valid_WithPrefix),
                    TransformTest(TransformTestSet.Enveloped_Valid_WithoutPrefix),
                    TransformTest(TransformTestSet.C14n_CanonicalizationMethod_WithComments, new ExpectedException(typeof(XmlReadException), "IDX30024:")),
                    TransformTest(TransformTestSet.C14n_ElementNotValid, new ExpectedException(typeof(XmlReadException), "IDX30024:")),
                    TransformTest(TransformTestSet.C14n_Transform_WithComments),
                    TransformTest(TransformTestSet.C14n_Transform_WithoutNS),
                    TransformTest(TransformTestSet.C14n_CanonicalizationMethod_WithComments, new ExpectedException(typeof(XmlReadException), "IDX30024:")),
                    TransformTest(TransformTestSet.C14n_Transform_WithoutNS),
                    TransformTest(TransformTestSet.TransformNull, new ExpectedException(typeof(XmlReadException), "IDX30105:")),
                };
            }
        }

        public static DSigSerializerTheoryData TransformTest(TransformTestSet testSet, ExpectedException expectedException = null, bool first = false)
        {
            return new DSigSerializerTheoryData
            {
                ExpectedException = expectedException ?? ExpectedException.NoExceptionExpected,
                First = first,
                TestId = testSet.TestId ?? nameof(testSet),
                Transform = testSet.Transform,
                Xml = testSet.Xml,
            };
        }

        [Theory, MemberData(nameof(ReadTransformsTheoryData))]
        public void ReadTransforms(DSigSerializerTheoryData theoryData)
        {
            TestUtilities.WriteHeader($"{this}.ReadTransforms", theoryData);
            var context = new CompareContext($"{this}.ReadTransforms, {theoryData.TestId}");
            try
            {
                var transforms = theoryData.Serializer.ReadTransforms(XmlUtilities.CreateDictionaryReader(theoryData.Xml));
                theoryData.ExpectedException.ProcessNoException(context);
                IdentityComparer.AreEqual(transforms, theoryData.Transforms, context);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context.Diffs);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<DSigSerializerTheoryData> ReadTransformsTheoryData
        {
            get
            {
                // uncomment to view exception displayed to user
                // ExpectedException.DefaultVerbose = true;

                return new TheoryData<DSigSerializerTheoryData>
                {
                    TransformsTest(TransformsTestSet.TransformsEmpty)
                };
            }
        }

        public static DSigSerializerTheoryData TransformsTest(TransformsTestSet testSet, ExpectedException expectedException = null, bool first = false)
        {
            return new DSigSerializerTheoryData
            {
                ExpectedException = expectedException ?? ExpectedException.NoExceptionExpected,
                First = first,
                TestId = testSet.TestId ?? nameof(testSet),
                Transforms = testSet.Transforms,
                Xml = testSet.Xml,
            };
        }

        [Theory, MemberData(nameof(WriteReferenceTheoryData))]
        public void WriteReference(DSigSerializerTheoryData theoryData)
        {
            var ms = new MemoryStream();
            var writer = XmlDictionaryWriter.CreateTextWriter(ms);
            DSigSerializer.Default.WriteReference(writer, theoryData.Reference);
            writer.Flush();
            var xml = Encoding.UTF8.GetString(ms.ToArray());

            IdentityComparer.AreEqual(theoryData.Xml, xml);
        }

        public static TheoryData<DSigSerializerTheoryData> WriteReferenceTheoryData
        {
            get
            {
                // uncomment to view exception displayed to user
                //ExpectedException.DefaultVerbose = true;

                return new TheoryData<DSigSerializerTheoryData>
                {
                    ReferenceTest(ReferenceTestSet.ReferenceWithNoUriIdWithPound),
                    ReferenceTest(ReferenceTestSet.ReferenceWithNoUriIdWithoutPound)
                };
            }
        }
    }

    public class DSigSerializerTheoryData : TheoryDataBase
    {
        public string Algorithm
        {
            get;
            set;
        }

        public string ElementName
        {
            get;
            set;
        }

        public HashAlgorithm HashAlgorithm
        {
            get;
            set;
        }

        public bool IncludeComments
        {
            get;
            set;
        }

        public bool IsCanonicalizationMethod
        {
            get;
            set;
        }

        public KeyInfo KeyInfo
        {
            get;
            set;
        }

        public SecurityKey SecurityKey
        {
            get;
            set;
        }

        public DSigSerializer Serializer
        {
            get;
            set;
        } = DSigSerializer.Default;

        public Signature Signature
        {
            get;
            set;
        }

        public SignedInfo SignedInfo
        {
            get;
            set;
        }

        public Reference Reference
        {
            get;
            set;
        }

        public override string ToString()
        {
            return $"'{TestId}', '{ExpectedException}'";
        }

        public string Transform
        {
            get;
            set;
        }

        public IList<string> Transforms
        {
            get;
            set;
        }

        public string Xml
        {
            get;
            set;
        }

        public XmlTokenStream XmlTokenStream
        {
            get;
            set;
        }

        public XmlWriter XmlWriter
        {
            get;
            set;
        }
    }
}

#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
