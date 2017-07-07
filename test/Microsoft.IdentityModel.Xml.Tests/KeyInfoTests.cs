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
        public void KeyInfoReadFrom(KeyInfoTheoryData theoryData)
        {
            TestUtilities.WriteHeader($"{this}.KeyInfoReadFrom", theoryData);
            var context = new CompareContext($"{this}.KeyInfoReadFrom, {theoryData.TestId}");
            try
            {
                var keyInfo = new KeyInfo();
                keyInfo.ReadFrom(XmlUtilities.CreateDictionaryReader(theoryData.Xml));
                theoryData.ExpectedException.ProcessNoException();

                IdentityComparer.AreKeyInfosEqual(keyInfo, theoryData.KeyInfo, context);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<KeyInfoTheoryData> KeyInfoReadFromTheoryData
        {
            get
            {
                // uncomment to view exception displayed to user
                // ExpectedException.DefaultVerbose = true;

                return new TheoryData<KeyInfoTheoryData>
                {
                    new KeyInfoTheoryData
                    {
                        ExpectedException = new ExpectedException(typeof(XmlReadException), "IDX21011:"),
                        First = true,
                        KeyInfo = ReferenceXml.KeyInfoWrongElement.KeyInfo,
                        TestId = nameof(ReferenceXml.KeyInfoWrongElement),
                        Xml = ReferenceXml.KeyInfoWrongElement.Xml,
                    },
                    new KeyInfoTheoryData
                    {
                        ExpectedException = new ExpectedException(typeof(XmlReadException), "IDX21011:"),
                        First = true,
                        KeyInfo = ReferenceXml.KeyInfoWrongNameSpace.KeyInfo,
                        TestId = nameof(ReferenceXml.KeyInfoWrongNameSpace),
                        Xml = ReferenceXml.KeyInfoWrongNameSpace.Xml,
                    },
                    new KeyInfoTheoryData
                    {
                        KeyInfo = ReferenceXml.KeyInfoSingleCertificate.KeyInfo,
                        TestId = nameof(ReferenceXml.KeyInfoSingleCertificate),
                        Xml = ReferenceXml.KeyInfoSingleCertificate.Xml
                    },
                    new KeyInfoTheoryData
                    {
                        KeyInfo = ReferenceXml.KeyInfoSingleIssuerSerial.KeyInfo,
                        TestId = nameof(ReferenceXml.KeyInfoSingleIssuerSerial),
                        Xml = ReferenceXml.KeyInfoSingleIssuerSerial.Xml,
                    },
                    new KeyInfoTheoryData
                    {
                        KeyInfo = ReferenceXml.KeyInfoSingleSKI.KeyInfo,
                        TestId = nameof(ReferenceXml.KeyInfoSingleSKI),
                        Xml = ReferenceXml.KeyInfoSingleSKI.Xml
                    },
                    new KeyInfoTheoryData
                    {
                        KeyInfo = ReferenceXml.KeyInfoSingleSubjectName.KeyInfo,
                        TestId = nameof(ReferenceXml.KeyInfoSingleSubjectName),
                        Xml = ReferenceXml.KeyInfoSingleSubjectName.Xml
                    },
                    new KeyInfoTheoryData
                    {
                        ExpectedException = new ExpectedException(typeof(XmlReadException), "IDX21015:"),
                        KeyInfo = ReferenceXml.KeyInfoMultipleCertificates.KeyInfo,
                        TestId = nameof(ReferenceXml.KeyInfoMultipleCertificates),
                        Xml = ReferenceXml.KeyInfoMultipleCertificates.Xml
                    },
                    new KeyInfoTheoryData
                    {
                        ExpectedException = new ExpectedException(typeof(XmlReadException), "IDX21015:"),
                        KeyInfo = ReferenceXml.KeyInfoMultipleIssuerSerial.KeyInfo,
                        TestId = nameof(ReferenceXml.KeyInfoMultipleIssuerSerial),
                        Xml = ReferenceXml.KeyInfoMultipleIssuerSerial.Xml
                    },
                    new KeyInfoTheoryData
                    {
                        ExpectedException = new ExpectedException(typeof(XmlReadException), "IDX21015:"),
                        KeyInfo = ReferenceXml.KeyInfoMultipleSKI.KeyInfo,
                        TestId = nameof(ReferenceXml.KeyInfoMultipleSKI),
                        Xml = ReferenceXml.KeyInfoMultipleSKI.Xml
                    },
                    new KeyInfoTheoryData
                    {
                        ExpectedException = new ExpectedException(typeof(XmlReadException), "IDX21015:"),
                        KeyInfo = ReferenceXml.KeyInfoMultipleSubjectName.KeyInfo,
                        TestId = nameof(ReferenceXml.KeyInfoMultipleSubjectName),
                        Xml = ReferenceXml.KeyInfoMultipleSubjectName.Xml
                    },
                    new KeyInfoTheoryData
                    {
                        KeyInfo = ReferenceXml.KeyInfoWithWhitespace.KeyInfo,
                        TestId = nameof(ReferenceXml.KeyInfoWithWhitespace),
                        Xml = ReferenceXml.KeyInfoWithWhitespace.Xml
                    },
                    new KeyInfoTheoryData
                    {
                        KeyInfo = ReferenceXml.KeyInfoWithUnknownX509DataElements.KeyInfo,
                        TestId = nameof(ReferenceXml.KeyInfoWithUnknownX509DataElements),
                        Xml = ReferenceXml.KeyInfoWithUnknownX509DataElements.Xml
                    },
                    new KeyInfoTheoryData
                    {
                        KeyInfo = ReferenceXml.KeyInfoWithAllElements.KeyInfo,
                        TestId = nameof(ReferenceXml.KeyInfoWithAllElements),
                        Xml = ReferenceXml.KeyInfoWithAllElements.Xml
                    },
                    new KeyInfoTheoryData
                    {
                        KeyInfo = ReferenceXml.KeyInfoWithUnknownElements.KeyInfo,
                        TestId = nameof(ReferenceXml.KeyInfoWithUnknownElements),
                        Xml = ReferenceXml.KeyInfoWithUnknownElements.Xml
                    },
                    new KeyInfoTheoryData
                    {
                        ExpectedException = new ExpectedException(typeof(XmlReadException), "IDX21017:", typeof(FormatException)),
                        KeyInfo = ReferenceXml.KeyInfoMalformedCertificate.KeyInfo,
                        TestId = nameof(ReferenceXml.KeyInfoMalformedCertificate),
                        Xml = ReferenceXml.KeyInfoMalformedCertificate.Xml,
                    }
                };
            }
        }
    }

    public class KeyInfoTheoryData : TheoryDataBase
    {
        public string Xml { get; set; }

        public KeyInfo KeyInfo { get; set; }
    }

}
