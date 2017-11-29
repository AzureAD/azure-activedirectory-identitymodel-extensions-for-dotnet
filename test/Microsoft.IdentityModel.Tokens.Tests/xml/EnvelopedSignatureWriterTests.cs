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
using Microsoft.IdentityModel.Tokens.Saml2;
using Microsoft.IdentityModel.Xml;
using Xunit;

#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant

namespace Microsoft.IdentityModel.Tokens.Xml.Tests
{
    public class EnvelopedSignatureWriterTests
    {
        [Theory, MemberData(nameof(ConstructorTheoryData))]
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
                return new TheoryData<EnvelopedSignatureTheoryData>
                {
                    new EnvelopedSignatureTheoryData
                    {
                        ExpectedException = ExpectedException.ArgumentNullException("IDX10000:"),
                        First = true,
                        ReferenceId = null,
                        SigningCredentials = null,
                        TestId = "Null XmlWriter",
                        XmlWriter = null
                    },
                    new EnvelopedSignatureTheoryData
                    {
                        ExpectedException = ExpectedException.ArgumentNullException("IDX10000:"),
                        ReferenceId = Guid.NewGuid().ToString(),
                        SigningCredentials = null,
                        TestId = "Null SigningCredentials",
                        XmlWriter = null
                    }
                };
            }
        }

        [Theory, MemberData(nameof(WriteXmlTheoryData))]
        public void WriteXml(EnvelopedSignatureTheoryData theoryData)
        {
            TestUtilities.WriteHeader($"{this}.WriteXml", theoryData);
            var context = new CompareContext($"{this}.WriteXml, {theoryData.TestId}");
            try
            {
                var saml2Serializer = new Saml2Serializer();
                var samlAssertion = saml2Serializer.ReadAssertion(XmlUtilities.CreateDictionaryReader(theoryData.Xml));
                var stream = new MemoryStream();
                var writer = XmlDictionaryWriter.CreateTextWriter(stream);
                samlAssertion.SigningCredentials = theoryData.SigningCredentials;
                saml2Serializer.WriteAssertion(writer, samlAssertion);
                writer.Flush();
                var xml = Encoding.UTF8.GetString(stream.ToArray());
                var samlAssertion2 = saml2Serializer.ReadAssertion(XmlUtilities.CreateDictionaryReader(xml));
                samlAssertion2.Signature.Verify(theoryData.SigningCredentials.Key);
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
                        Xml =  ReferenceTokens.Saml2Token_Valid
                    }
                };
            }
        }
    }
}

#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
