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
using Microsoft.IdentityModel.TestUtils;
using Xunit;

#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant

namespace Microsoft.IdentityModel.Xml.Tests
{
    public class EncryptionMethodTests
    {
        [Fact]
        public void GetSets()
        {
            var type = typeof(EncryptionMethod);
            var properties = type.GetProperties();
            Assert.True(properties.Length == 2, $"Number of properties has changed from 2 to: {properties.Length}, adjust tests");

            var EncryptionMethod = new EncryptionMethod();
            var context = new GetSetContext
            {
                PropertyNamesAndSetGetValue = new List<KeyValuePair<string, List<object>>>
                {
                    new KeyValuePair<string, List<object>>("DigestMethod", new List<object>{null, Guid.NewGuid().ToString()}),
                    new KeyValuePair<string, List<object>>("KeyAlgorithm", new List<object>{null, Guid.NewGuid().ToString()}),
                },
                Object = EncryptionMethod
            };

            TestUtilities.GetSet(context);
            TestUtilities.AssertFailIfErrors($"{this}.GetSets", context.Errors);
        }

        [Theory, MemberData(nameof(ConstructorTheoryData))]
        public void Constructor(EncryptionMethodTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.Constructor", theoryData);
            try
            {
                var EncryptionMethod = new EncryptionMethod(theoryData.KeyAlgorithm);
                IdentityComparer.AreEqual(EncryptionMethod.KeyAlgorithm, theoryData.KeyAlgorithm, context);
                theoryData.ExpectedException.ProcessNoException(context);
            }
            catch (Exception exception)
            {
                theoryData.ExpectedException.ProcessException(exception, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<EncryptionMethodTheoryData> ConstructorTheoryData()
        {
            return new TheoryData<EncryptionMethodTheoryData>
            {
                new EncryptionMethodTheoryData
                {
                    First = true,
                    KeyAlgorithm = null,
                    TestId = "NullAlgorithm"
                },
                new EncryptionMethodTheoryData
                {
                    KeyAlgorithm = "",
                    TestId = "EmptyAlgorithm"
                },
                new EncryptionMethodTheoryData
                {
                    KeyAlgorithm = Guid.NewGuid().ToString(),
                    TestId = "valid"
                },
            };
        }
    }

    public class EncryptionMethodTheoryData : TheoryDataBase
    {
        public string KeyAlgorithm { get; set; }
    }
}

#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant
