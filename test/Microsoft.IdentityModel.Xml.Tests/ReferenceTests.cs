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
using System.Security.Cryptography;
using Microsoft.IdentityModel.Tests;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace Microsoft.IdentityModel.Xml.Tests
{
#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant

    public class ReferenceTests
    {
        [Fact]
        public void GetSets()
        {
            var type = typeof(Reference);
            var properties = type.GetProperties();
            Assert.True(properties.Length == 8, $"Number of properties has changed from 8 to: {properties.Length}, adjust tests");
            var context = new GetSetContext
            {
                PropertyNamesAndSetGetValue = new List<KeyValuePair<string, List<object>>>
                {
                    new KeyValuePair<string, List<object>>("Id", new List<object>{(string)null, Guid.NewGuid().ToString(), Guid.NewGuid().ToString()}),
                    new KeyValuePair<string, List<object>>("Prefix", new List<object>{(string)null, Guid.NewGuid().ToString(), Guid.NewGuid().ToString()}),
                    new KeyValuePair<string, List<object>>("DigestMethod", new List<object>{null, Guid.NewGuid().ToString(), Guid.NewGuid().ToString()}),
                    new KeyValuePair<string, List<object>>("DigestValue", new List<object>{(string)null, Guid.NewGuid().ToString(), Guid.NewGuid().ToString()}),
                    new KeyValuePair<string, List<object>>("TokenStream", new List<object>{(XmlTokenStream)null, new XmlTokenStream(), new XmlTokenStream()}),
                    new KeyValuePair<string, List<object>>("Type", new List<object>{(string)null, Guid.NewGuid().ToString(), Guid.NewGuid().ToString()}),
                    new KeyValuePair<string, List<object>>("Uri", new List<object>{(string)null, Guid.NewGuid().ToString(), Guid.NewGuid().ToString()}),
                },
                Object = new Reference(),
            };

            TestUtilities.GetSet(context);
            TestUtilities.AssertFailIfErrors($"{this}.GetSets", context.Errors);
        }

        [Theory, MemberData("VerifyTheoryData")]
        public void Verify(ReferenceTheroryData theoryData)
        {
            TestUtilities.WriteHeader($"{this}.Verify", theoryData);
            var context = new CompareContext($"{this}.Verify, {theoryData.TestId}");
            try
            {
                theoryData.Reference.Verify(theoryData.ProviderFactory);
                theoryData.ExpectedException.ProcessNoException(context);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<ReferenceTheroryData> VerifyTheoryData
        {
            get
            {
                // uncomment to view exception displayed to user
                ExpectedException.DefaultVerbose = true;

                return new TheoryData<ReferenceTheroryData>()
                {
                    new ReferenceTheroryData
                    {
                        ExpectedException = ExpectedException.ArgumentNullException(),
                        TestId = "CryptoProviderFactory == null"
                    },
                    new ReferenceTheroryData
                    {
                        ExpectedException = new ExpectedException(typeof(XmlValidationException), "IDX21202"),
                        ProviderFactory = CryptoProviderFactory.Default,
                        TestId = "XmlTokenStream == null"
                    },
                    new ReferenceTheroryData
                    {
                        ExpectedException = new ExpectedException(typeof(XmlValidationException), "IDX21208"),
                        ProviderFactory = new CustomCryptoProviderFactory(),
                        Reference = Default.Reference,
                        TestId = "DigestMethod Not Supported"
                    },
                    new ReferenceTheroryData
                    {
                        ExpectedException = new ExpectedException(typeof(XmlValidationException), "IDX21209"),
                        ProviderFactory = new CustomCryptoProviderFactory
                        {
                            SupportedAlgorithms = new List<string>{Default.ReferenceDigestMethod}
                        },
                        Reference = Default.Reference,
                        TestId = "CryptoProviderFactory returns null HashAlgorithm"
                    }
                };
            }
        }
#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
    }

    public class ReferenceTheroryData : TheoryDataBase
    {
        public CryptoProviderFactory ProviderFactory
        {
            get;
            set;
        }

        public string DigestMethod
        {
            get;
            set;
        }

        public string DigestValue
        {
            get;
            set;
        }

        public Reference Reference
        {
            get;
            set;
        } = new Reference();

        public IEnumerable<string> Transforms
        {
            get;
            set;
        }

        public string Xml
        {
            get;
            set;
        }
    }
}
