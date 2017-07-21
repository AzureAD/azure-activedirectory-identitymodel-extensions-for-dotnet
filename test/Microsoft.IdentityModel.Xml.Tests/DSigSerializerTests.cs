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
using System.Security.Cryptography;
using System.Xml;
using Microsoft.IdentityModel.Tests;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace Microsoft.IdentityModel.Xml.Tests
{
#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant

    public class DSigSerializerTests
    {
        [Theory, MemberData("ReadKeyInfoTheoryData")]
        public void ReadKeyInfo(DSigSerializerTheoryData theoryData)
        {
            TestUtilities.WriteHeader($"{this}.ReadKeyInfo", theoryData);
            var context = new CompareContext($"{this}.ReadKeyInfo, {theoryData.TestId}");
            try
            {
                var keyInfo = theoryData.Serializer.ReadKeyInfo(XmlUtilities.CreateDictionaryReader(theoryData.Xml));
                theoryData.ExpectedException.ProcessNoException(context.Diffs);
                IdentityComparer.AreKeyInfosEqual(keyInfo, theoryData.KeyInfo, context);
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
                    KeyInfoTest(KeyInfoTestSet.MalformedCertificate, new ExpectedException(typeof(XmlReadException), "IDX21017:", typeof(FormatException)), true),
                    KeyInfoTest(KeyInfoTestSet.MultipleCertificates, new ExpectedException(typeof(XmlReadException), "IDX21015:")),
                    KeyInfoTest(KeyInfoTestSet.MultipleIssuerSerial, new ExpectedException(typeof(XmlReadException), "IDX21015:")),
                    KeyInfoTest(KeyInfoTestSet.MultipleSKI, new ExpectedException(typeof(XmlReadException), "IDX21015:")),
                    KeyInfoTest(KeyInfoTestSet.MultipleSubjectName, new ExpectedException(typeof(XmlReadException), "IDX21015:")),
                    KeyInfoTest(KeyInfoTestSet.SingleCertificate),
                    KeyInfoTest(KeyInfoTestSet.SingleIssuerSerial),
                    KeyInfoTest(KeyInfoTestSet.SingleSKI),
                    KeyInfoTest(KeyInfoTestSet.SingleSubjectName),
                    KeyInfoTest(KeyInfoTestSet.WithWhitespace),
                    KeyInfoTest(KeyInfoTestSet.WithUnknownX509DataElements),
                    KeyInfoTest(KeyInfoTestSet.WithAllElements),
                    KeyInfoTest(KeyInfoTestSet.WithUnknownElements),
                    KeyInfoTest(KeyInfoTestSet.WrongNamespace, new ExpectedException(typeof(XmlReadException), "IDX21011:")),
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

        [Theory, MemberData("ReadSignatureTheoryData")]
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
                    SignatureTest(SignatureTestSet.UnknownSignatureAlgorithm)
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

        [Theory, MemberData("ReadSignedInfoTheoryData")]
        public void ReadSignedInfo(DSigSerializerTheoryData theoryData)
        {
            TestUtilities.WriteHeader($"{this}.SignedInfoReadFrom", theoryData);
            var context = new CompareContext($"{this}.SignedInfoReadFrom, {theoryData.TestId}");
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
                // ExpectedException.DefaultVerbose = true;

                return new TheoryData<DSigSerializerTheoryData>
                {
                    SignedInfoTest(SignedInfoTestSet.CanonicalizationMethodMissing,
                        new ExpectedException(typeof(XmlReadException), "IDX21011:"), true),
                    SignedInfoTest(SignedInfoTestSet.MissingDigestMethod,
                        new ExpectedException(typeof(XmlReadException), "IDX21011: Unable to read XML. Expecting XmlReader to be at ns.element: 'http://www.w3.org/2000/09/xmldsig#.DigestMethod'")),
                    SignedInfoTest(SignedInfoTestSet.MissingDigestValue,
                        new ExpectedException(typeof(XmlReadException), "IDX21011: Unable to read XML. Expecting XmlReader to be at ns.element: 'http://www.w3.org/2000/09/xmldsig#.DigestValue'")),
                    SignedInfoTest(SignedInfoTestSet.NoTransforms),
                    SignedInfoTest(SignedInfoTestSet.StartsWithWhiteSpace),
                    SignedInfoTest(SignedInfoTestSet.TransformsMissing),
                    SignedInfoTest(SignedInfoTestSet.TwoReferences,
                        new ExpectedException(typeof(XmlReadException), "IDX21020: Unable to read XML. A second <Reference> element was found")),
                    SignedInfoTest(SignedInfoTestSet.ReferenceMissing,
                        new ExpectedException(typeof(XmlReadException), "IDX21011: Unable to read XML. Expecting XmlReader to be at ns.element: 'http://www.w3.org/2000/09/xmldsig#.Reference'")),
                    SignedInfoTest(SignedInfoTestSet.ReferenceDigestValueNotBase64),
                    SignedInfoTest(SignedInfoTestSet.UnknownReferenceTransform),
                    SignedInfoTest(SignedInfoTestSet.Valid)
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

        [Theory, MemberData("ReadTransformTheoryData")]
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
                    TransformTest(TransformTestSet.Enveloped_AlgorithmMissing, new ExpectedException(typeof(XmlReadException), "IDX21105:")),
                    TransformTest(TransformTestSet.AlgorithmNull, new ExpectedException(typeof(XmlReadException), "IDX21105:")),
                    TransformTest(TransformTestSet.Enveloped_Valid_WithPrefix),
                    TransformTest(TransformTestSet.Enveloped_Valid_WithoutPrefix),
                    TransformTest(TransformTestSet.C14n_CanonicalizationMethod_WithComments, new ExpectedException(typeof(XmlReadException), "IDX21024:")),
                    TransformTest(TransformTestSet.C14n_ElementNotValid, new ExpectedException(typeof(XmlReadException), "IDX21024:")),
                    TransformTest(TransformTestSet.C14n_Transform_WithComments),
                    TransformTest(TransformTestSet.C14n_Transform_WithoutNS),
                    TransformTest(TransformTestSet.C14n_CanonicalizationMethod_WithComments, new ExpectedException(typeof(XmlReadException), "IDX21024:")),
                    TransformTest(TransformTestSet.C14n_Transform_WithoutNS),
                    TransformTest(TransformTestSet.TransformNull, new ExpectedException(typeof(XmlReadException), "IDX21105:")),
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
#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
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
        } = new DSigSerializer();

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

        public override string ToString()
        {
            return $"'{TestId}', '{ExpectedException}'";
        }

        public string Transform
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
