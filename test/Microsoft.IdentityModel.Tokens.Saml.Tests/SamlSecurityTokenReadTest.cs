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
using Microsoft.IdentityModel.Tests;
using Microsoft.IdentityModel.Tokens.Saml;
using Xunit;

namespace Microsoft.IdentityModel.Tokens.Saml.Tests
{
    public class SamlSecurityTokenReadTest
    {
#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant
        [Theory, MemberData("SamlReadFromTheoryData")]
#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
        public void SamlSecurityTokenReadFrom(SamlSecurityTokenTheoryData theoryData)
        {
            TestUtilities.WriteHeader($"{this}.SamlSecurityTokenReadFrom", theoryData);
            var context = new CompareContext($"{this}.SamlSecurityTokenReadFrom, {theoryData.TestId}");
            try
            {
                var sr = new StringReader(theoryData.SamlSecurityTokenTestSet.Xml);
                var reader = XmlDictionaryReader.CreateDictionaryReader(XmlReader.Create(sr));
                var samlSerializer = theoryData.SamlSerializer;
                var assertion = samlSerializer.ReadAssertion(reader);
                theoryData.ExpectedException.ProcessNoException();

                IdentityComparer.AreEqual(assertion, theoryData.SamlSecurityTokenTestSet.SamlSecurityToken.Assertion, context);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<SamlSecurityTokenTheoryData> SamlReadFromTheoryData
        {
            get
            {
                var theoryData = new TheoryData<SamlSecurityTokenTheoryData>();

                theoryData.Add(new SamlSecurityTokenTheoryData
                {
                    First = true,
                    SamlSecurityTokenTestSet = RefrenceTokens.SamlSecurityTokenValid,
                    SamlSerializer = new SamlSerializer(),
                    TestId = nameof(RefrenceTokens.SamlSecurityTokenValid)
                });

                return theoryData;
            }
        }

    }

    public class SamlSecurityTokenTheoryData : TheoryDataBase
    {
        public SamlSecurityTokenTestSet SamlSecurityTokenTestSet { get; set; }

        public SamlSerializer SamlSerializer { get; set; }
    }
}
