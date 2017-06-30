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
using System.Xml;
using Microsoft.IdentityModel.Tests;
using Xunit;

namespace Microsoft.IdentityModel.Xml.Tests
{
    public class KeyInfoTests
    {
#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant
        [Theory, MemberData("KeyInfoReadFromTheoryData")]
#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
        public void KeyInfoReadFrom(DSigTheoryData theoryData)
        {
            TestUtilities.WriteHeader($"{this}.KeyInfoReadFrom", theoryData);
            var context = new CompareContext($"{this}.QueryStringTest, {theoryData.TestId}");
            try
            {
                var sr = new StringReader(theoryData.KeyInfoTestSet.Xml);
                var reader = XmlDictionaryReader.CreateDictionaryReader(XmlReader.Create(sr));
                var keyInfo = new KeyInfo();
                keyInfo.ReadFrom(reader);
                theoryData.ExpectedException.ProcessNoException();

                IdentityComparer.AreEqual(keyInfo, theoryData.KeyInfoTestSet.KeyInfo, context);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<DSigTheoryData> KeyInfoReadFromTheoryData
        {
            get
            {
                // uncomment to view exception displayed to user
                // ExpectedException.DefaultVerbose = true;

                return new TheoryData<DSigTheoryData>
                {
                    new DSigTheoryData
                    {
                        ExpectedException = new ExpectedException(typeof(XmlReadException), "IDX21011:"),
                        First = true,
                        KeyInfoTestSet = ReferenceXml.KeyInfoWrongElement,
                        TestId = nameof(ReferenceXml.KeyInfoWrongElement)
                    },
                    new DSigTheoryData
                    {
                        ExpectedException = new ExpectedException(typeof(XmlReadException), "IDX21011:"),
                        First = true,
                        KeyInfoTestSet = ReferenceXml.KeyInfoWrongNameSpace,
                        TestId = nameof(ReferenceXml.KeyInfoWrongNameSpace)
                    },
                    new DSigTheoryData
                    {
                        KeyInfoTestSet = ReferenceXml.KeyInfoSingleCertificate,
                        TestId = nameof(ReferenceXml.KeyInfoSingleCertificate)
                    },
                    new DSigTheoryData
                    {
                        KeyInfoTestSet = ReferenceXml.KeyInfoSingleIssuerSerial,
                        TestId = nameof(ReferenceXml.KeyInfoSingleIssuerSerial)
                    },
                    new DSigTheoryData
                    {
                        KeyInfoTestSet = ReferenceXml.KeyInfoSingleSKI,
                        TestId = nameof(ReferenceXml.KeyInfoSingleSKI)
                    },
                    new DSigTheoryData
                    {
                        KeyInfoTestSet = ReferenceXml.KeyInfoSingleSubjectName,
                        TestId = nameof(ReferenceXml.KeyInfoSingleSubjectName)
                    },
                    new DSigTheoryData
                    {
                        ExpectedException = new ExpectedException(typeof(XmlReadException), "IDX21015:"),
                        KeyInfoTestSet = ReferenceXml.KeyInfoMultipleCertificates,
                        TestId = nameof(ReferenceXml.KeyInfoMultipleCertificates)
                    },
                    new DSigTheoryData
                    {
                        ExpectedException = new ExpectedException(typeof(XmlReadException), "IDX21015:"),
                        KeyInfoTestSet = ReferenceXml.KeyInfoMultipleIssuerSerial,
                        TestId = nameof(ReferenceXml.KeyInfoMultipleIssuerSerial)
                    },
                    new DSigTheoryData
                    {
                        ExpectedException = new ExpectedException(typeof(XmlReadException), "IDX21015:"),
                        KeyInfoTestSet = ReferenceXml.KeyInfoMultipleSKI,
                        TestId = nameof(ReferenceXml.KeyInfoMultipleSKI)
                    },
                    new DSigTheoryData
                    {
                        ExpectedException = new ExpectedException(typeof(XmlReadException), "IDX21015:"),
                        KeyInfoTestSet = ReferenceXml.KeyInfoMultipleSubjectName,
                        TestId = nameof(ReferenceXml.KeyInfoMultipleSubjectName)
                    },
                    new DSigTheoryData
                    {
                        KeyInfoTestSet = ReferenceXml.KeyInfoWithWhitespace,
                        TestId = nameof(ReferenceXml.KeyInfoWithWhitespace),
                    },
                    new DSigTheoryData
                    {
                        KeyInfoTestSet = ReferenceXml.KeyInfoWithUnknownX509DataElements,
                        TestId = nameof(ReferenceXml.KeyInfoWithUnknownX509DataElements)
                    },
                    new DSigTheoryData
                    {
                        KeyInfoTestSet = ReferenceXml.KeyInfoWithAllElements,
                        TestId = nameof(ReferenceXml.KeyInfoWithAllElements)
                    },
                    new DSigTheoryData
                    {
                        KeyInfoTestSet = ReferenceXml.KeyInfoWithUnknownElements,
                        TestId = nameof(ReferenceXml.KeyInfoWithUnknownElements)
                    },
                    new DSigTheoryData
                    {
                        ExpectedException = new ExpectedException(typeof(XmlReadException), "IDX21017:", typeof(FormatException)),
                        KeyInfoTestSet = ReferenceXml.KeyInfoMalformedCertificate,
                        TestId = nameof(ReferenceXml.KeyInfoMalformedCertificate)
                    }
                };
            }
        }
    }
}
