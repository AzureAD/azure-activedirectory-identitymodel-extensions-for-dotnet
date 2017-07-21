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
using Microsoft.IdentityModel.Xml;
using Xunit;

namespace Microsoft.IdentityModel.Xml.Tests
{
    public class ExclusiveCanonicalizationTransformTests
    {
#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant
        [Theory, MemberData("ConstructorTheoryData")]
        public void Constructor(ExclusiveCanonicalizationTransformTheoryData theoryData)
        {
            TestUtilities.WriteHeader($"{this}.Constructor", theoryData);
            var transform = new ExclusiveCanonicalizationTransform(theoryData.IncludeComments);

            Assert.Equal(transform.IncludeComments, theoryData.IncludeComments);
        }

        public static TheoryData<ExclusiveCanonicalizationTransformTheoryData> ConstructorTheoryData
        {
            get
            {
                // uncomment to view exception displayed to user
                // ExpectedException.DefaultVerbose = true;

                return new TheoryData<ExclusiveCanonicalizationTransformTheoryData>
                {
                    new ExclusiveCanonicalizationTransformTheoryData
                    {
                        First = true,
                        IncludeComments = false,
                        TestId = "ExclusiveC14n, , IncludeComments : true"
                    },
                    new ExclusiveCanonicalizationTransformTheoryData
                    {
                        IncludeComments = true,
                        TestId = "ExclusiveC14n, IncludeComments : true"
                    }
                };
            }
        }

        [Theory, MemberData("ProcessAndDigestTheoryData")]
        public void ProcessAndDigest(ExclusiveCanonicalizationTransformTheoryData theoryData)
        {
            TestUtilities.WriteHeader($"{this}", "ProcessAndDigest", true);
            var context = new CompareContext($"{this}.ProcessAndDigest, {theoryData.TestId}");
            try
            {
                theoryData.Transform.ProcessAndDigest(theoryData.XmlTokenStream, theoryData.HashAlgorithm);
                theoryData.ExpectedException.ProcessNoException(context);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<ExclusiveCanonicalizationTransformTheoryData> ProcessAndDigestTheoryData
        {
            get
            {
                // uncomment to view exception displayed to user
                // ExpectedException.DefaultVerbose = true;

                return new TheoryData<ExclusiveCanonicalizationTransformTheoryData>
                {
                    new ExclusiveCanonicalizationTransformTheoryData
                    {
                        ExpectedException = ExpectedException.ArgumentNullException("tokenStream"),
                        First = true,
                        HashAlgorithm = SHA256.Create(),
                        TestId = "TokenStream null",
                        Transform = new ExclusiveCanonicalizationTransform(false)
                    },
                    new ExclusiveCanonicalizationTransformTheoryData
                    {
                        ExpectedException = ExpectedException.ArgumentNullException("hash"),
                        Transform = new ExclusiveCanonicalizationTransform(false),
                        TestId = "hash null",
                        XmlTokenStream = XmlUtilities.CreateXmlTokenStream(Default.OuterXml)
                    },
                    new ExclusiveCanonicalizationTransformTheoryData
                    {
                        HashAlgorithm = SHA256.Create(),
                        Transform = new ExclusiveCanonicalizationTransform(false),
                        TestId = "reader, hash set",
                        XmlTokenStream = XmlUtilities.CreateXmlTokenStream(Default.OuterXml)
                    }
                };
            }
        }
#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
    }

    public class ExclusiveCanonicalizationTransformTheoryData : TheoryDataBase
    {
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

        public override string ToString()
        {
            return $"'{TestId}', '{ExpectedException}'";
        }

        public ExclusiveCanonicalizationTransform Transform
        {
            get;
            set;
        }

        public XmlTokenStream XmlTokenStream
        {
            get;
            set;
        }
    }
}
