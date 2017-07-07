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
using System.Xml;
using Microsoft.IdentityModel.Tests;
using Xunit;

namespace Microsoft.IdentityModel.Xml.Tests
{
    public class SignedInfoTests
    {
#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant
        [Theory, MemberData("SignedInfoConstructorTheoryData")]
#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
        public void SignedInfoConstructor(SignedInfoTheoryData theoryData)
        {
            TestUtilities.WriteHeader($"{this}.SignedInfoConstructor", theoryData);
            List<string> errors = new List<string>();
            try
            {
                var signedInfo = new SignedInfo();
                if (signedInfo.Reference != null)
                    errors.Add("signedInfo.Reference != null");

                if (!string.IsNullOrEmpty(signedInfo.SignatureAlgorithm))
                    errors.Add("!string.IsNullOrEmpty(signedInfo.SignatureAlgorithm)");

                theoryData.ExpectedException.ProcessNoException();
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex);
            }

            TestUtilities.AssertFailIfErrors(errors);
        }

        public static TheoryData<SignedInfoTheoryData> SignedInfoConstructorTheoryData
        {
            get
            {
                return new TheoryData<SignedInfoTheoryData>
                {
                    new SignedInfoTheoryData
                    {
                        First = true,
                        TestId = "Constructor"
                    }
                };
            }
        }

#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant
        [Theory, MemberData("SignedInfoReadFromTheoryData")]
#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
        public void SignedInfoReadFrom(SignedInfoTheoryData theoryData)
        {
            TestUtilities.WriteHeader($"{this}.SignedInfoReadFrom", theoryData);
            var context = new CompareContext($"{this}.SignedInfoReadFrom, {theoryData.TestId}");

            var errors = new List<string>();
            try
            {
                var sr = new StringReader(theoryData.Xml);
                var reader = XmlDictionaryReader.CreateDictionaryReader(XmlReader.Create(sr));
                var signedInfo = new SignedInfo();
                signedInfo.ReadFrom(reader);
                theoryData.ExpectedException.ProcessNoException(context.Diffs);
                if (theoryData.ExpectedException.TypeExpected == null)
                    IdentityComparer.AreEqual(signedInfo, theoryData.SignedInfo, context);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<SignedInfoTheoryData> SignedInfoReadFromTheoryData
        {
            get
            {
                // uncomment to view exception displayed to user
                // ExpectedException.DefaultVerbose = true;

                return new TheoryData<SignedInfoTheoryData>
                {
                    new SignedInfoTheoryData
                    {
                        First = true,
                        SignedInfo = ReferenceXml.SignedInfoValid.SignedInfo,
                        TestId = nameof(ReferenceXml.SignedInfoValid),
                        Xml = ReferenceXml.SignedInfoValid.Xml
                    },
                    new SignedInfoTheoryData
                    {
                        SignedInfo = ReferenceXml.SignInfoStartsWithWhiteSpace.SignedInfo,
                        TestId = nameof(ReferenceXml.SignInfoStartsWithWhiteSpace),
                        Xml = ReferenceXml.SignInfoStartsWithWhiteSpace.Xml
                    },
                    new SignedInfoTheoryData
                    {
                        ExpectedException = new ExpectedException(typeof(XmlReadException), "IDX21011:"),
                        SignedInfo = ReferenceXml.SignedInfoCanonicalizationMethodMissing.SignedInfo,
                        TestId = nameof(ReferenceXml.SignedInfoCanonicalizationMethodMissing),
                        Xml = ReferenceXml.SignedInfoCanonicalizationMethodMissing.Xml,
                    },
                    new SignedInfoTheoryData
                    {
                        ExpectedException = new ExpectedException(typeof(XmlReadException), "IDX21011: Unable to read xml. Expecting XmlReader to be at ns.element: 'http://www.w3.org/2000/09/xmldsig#.Reference'"),
                        SignedInfo = ReferenceXml.SignedInfoReferenceMissing.SignedInfo,
                        TestId = nameof(ReferenceXml.SignedInfoReferenceMissing),
                        Xml = ReferenceXml.SignedInfoReferenceMissing.Xml
                    },
                    new SignedInfoTheoryData
                    {
                        ExpectedException = new ExpectedException(typeof(XmlReadException), "Unable to read xml. Expecting XmlReader to be at ns.element: 'http://www.w3.org/2000/09/xmldsig#.Transforms'"),
                        SignedInfo = ReferenceXml.SignedInfoTransformsMissing.SignedInfo,
                        TestId = nameof(ReferenceXml.SignedInfoTransformsMissing),
                        Xml = ReferenceXml.SignedInfoTransformsMissing.Xml,
                    },
                    new SignedInfoTheoryData
                    {
                        ExpectedException = new ExpectedException(typeof(XmlReadException), "IDX21011: Unable to read xml. Expecting XmlReader to be at ns.element: 'http://www.w3.org/2000/09/xmldsig#.Transforms', "),
                        SignedInfo = ReferenceXml.SignedInfoNoTransforms.SignedInfo,
                        TestId = nameof(ReferenceXml.SignedInfoNoTransforms),
                        Xml = ReferenceXml.SignedInfoNoTransforms.Xml,
                    },
                    new SignedInfoTheoryData
                    {
                        ExpectedException = new ExpectedException(typeof(XmlException), "IDX21018: Unable to read xml. A Reference contains an unknown transform "),
                        SignedInfo = ReferenceXml.SignedInfoUnknownCanonicalizationtMethod.SignedInfo,
                        TestId = nameof(ReferenceXml.SignedInfoUnknownCanonicalizationtMethod),
                        Xml = ReferenceXml.SignedInfoUnknownCanonicalizationtMethod.Xml,
                    },
                    new SignedInfoTheoryData
                    {
                        ExpectedException = new ExpectedException(typeof(XmlException), "IDX21018: Unable to read xml. A Reference contains an unknown transform "),
                        SignedInfo = ReferenceXml.SignedInfoUnknownTransform.SignedInfo,
                        TestId = nameof(ReferenceXml.SignedInfoUnknownTransform),
                        Xml = ReferenceXml.SignedInfoUnknownTransform.Xml,
                    },
                    new SignedInfoTheoryData
                    {
                        ExpectedException = new ExpectedException(typeof(XmlReadException), "IDX21011: Unable to read xml. Expecting XmlReader to be at ns.element: 'http://www.w3.org/2000/09/xmldsig#.DigestMethod', "),
                        SignedInfo = ReferenceXml.SignedInfoMissingDigestMethod.SignedInfo,
                        TestId = nameof(ReferenceXml.SignedInfoMissingDigestMethod),
                        Xml = ReferenceXml.SignedInfoMissingDigestMethod.Xml,
                    },
                    new SignedInfoTheoryData
                    {
                        ExpectedException = new ExpectedException(typeof(XmlReadException), "IDX21011: Unable to read xml. Expecting XmlReader to be at ns.element: 'http://www.w3.org/2000/09/xmldsig#.DigestValue', "),
                        SignedInfo = ReferenceXml.SignedInfoMissingDigestValue.SignedInfo,
                        TestId = nameof(ReferenceXml.SignedInfoMissingDigestValue),
                        Xml = ReferenceXml.SignedInfoMissingDigestValue.Xml,
                    }
                };
            }
        }
    }

    public class SignedInfoTheoryData : TheoryDataBase
    {
        public SignedInfo SignedInfo { get; set; }

        public string Xml { get; set; }
    }
}
