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
using Microsoft.IdentityModel.Tests;
using Xunit;

namespace Microsoft.IdentityModel.Xml.Tests
{
    public class EnvelopedSignatureWriterTests
    {

#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant
        [Theory, MemberData("ConstructorTheoryData")]
        public void Constructor(EnvelopedSignatureTheoryData theoryData)
        {
            TestUtilities.WriteHeader($"{this}.Constructor", theoryData);
            try
            {
                var envelopedWriter = new EnvelopedSignatureWriter(theoryData.XmlWriter, theoryData.SigningCredentials, theoryData.ReferenceId);
                theoryData.ExpectedException.ProcessNoException();
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex);
            }
        }

        public static TheoryData<EnvelopedSignatureTheoryData> ConstructorTheoryData
        {
            get
            {
                var theoryData = new TheoryData<EnvelopedSignatureTheoryData>();

                theoryData.Add(new EnvelopedSignatureTheoryData
                {
                    ExpectedException = ExpectedException.ArgumentNullException("IDX10000:"),
                    First = true,
                    ReferenceId = null,
                    SigningCredentials = null,
                    TestId = "Null XmlWriter",
                    XmlWriter = null
                });


                var ms = new MemoryStream();
                var xmlWriter = XmlWriter.Create(ms);

                theoryData.Add(new EnvelopedSignatureTheoryData
                {
                    ExpectedException = ExpectedException.ArgumentNullException("IDX10000:"),
                    ReferenceId = null,
                    SigningCredentials = KeyingMaterial.RSASigningCreds_2048,
                    TestId = "Null ReferenceId",
                    XmlWriter = xmlWriter
                });

                theoryData.Add(new EnvelopedSignatureTheoryData
                {
                    ExpectedException = ExpectedException.ArgumentNullException("IDX10000:"),
                    ReferenceId = string.Empty,
                    SigningCredentials = KeyingMaterial.RSASigningCreds_2048,
                    TestId = "Empty ReferenceId",
                    XmlWriter = xmlWriter
                });

                theoryData.Add(new EnvelopedSignatureTheoryData
                {
                    ExpectedException = ExpectedException.ArgumentNullException("IDX10000:"),
                    ReferenceId = Guid.NewGuid().ToString(),
                    SigningCredentials = null,
                    TestId = "Null SigningCredentials",
                    XmlWriter = null
                });

                return theoryData;
            }
        }

        [Theory, MemberData("WriteXmlTheoryData")]
        public void WriteXml(EnvelopedSignatureTheoryData theoryData)
        {
            TestUtilities.WriteHeader($"{this}.WriteXml", theoryData);
            var context = new CompareContext($"{this}.WriteXml, {theoryData.TestId}");
            try
            {
                var stream = new MemoryStream();
                var writer = XmlDictionaryWriter.CreateTextWriter(stream);
                var envelopedWriter = new EnvelopedSignatureWriter(writer, theoryData.SigningCredentials, theoryData.ReferenceId);
                envelopedWriter.WriteStartElement("OuterXml");
                envelopedWriter.WriteAttributeString(XmlSignatureConstants.Attributes.Id, Default.ReferenceUri);
                envelopedWriter.WriteStartElement("InnerXml");
                envelopedWriter.WriteAttributeString("innerAttribute", "innerValue");
                envelopedWriter.WriteEndElement();
                envelopedWriter.WriteEndElement();
                var xml = Encoding.UTF8.GetString(stream.ToArray());
                theoryData.ExpectedException.ProcessNoException(context);
                var envelopedReader = new EnvelopedSignatureReader(XmlUtilities.CreateDictionaryReader(xml));
                while (envelopedReader.Read());
                envelopedReader.Signature.Verify(theoryData.SigningCredentials.Key);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<EnvelopedSignatureTheoryData> WriteXmlTheoryData
        {
            get
            {
                return new TheoryData<EnvelopedSignatureTheoryData>()
                {
                    new EnvelopedSignatureTheoryData
                    {
                        ReferenceId = Default.ReferenceUri,
                        SigningCredentials = Default.AsymmetricSigningCredentials,
                        Xml = Default.OuterXml
                    }
                };
            }
        }
#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
    }
}
