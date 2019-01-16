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
using System.Collections.ObjectModel;
using Microsoft.IdentityModel.TestUtils;
using Microsoft.IdentityModel.Tokens;
using Xunit;

#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant

namespace Microsoft.IdentityModel.JsonWebTokens.Tests
{
    public class JwtTokenUtilitiesTests
    {
        [Theory, MemberData(nameof(KeyMatchTheoryData))]
        public void FindKeyMatch(KeyMatchTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.SegmentCanRead", theoryData);

            try
            {
                var matchKey = JwtTokenUtilities.FindKeyMatch(theoryData.Kid, theoryData.X5t, theoryData.SecurityKey, theoryData.SecurityKeys);
                if (!object.ReferenceEquals(matchKey, theoryData.Match))
                    context.Diffs.Add("!object.ReferenceEquals(matchKey, theoryData.Match)");

                theoryData.ExpectedException.ProcessNoException(context);
            }
            catch(Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<KeyMatchTheoryData> KeyMatchTheoryData()
        {
            var x509SecurityKey1 = KeyingMaterial.X509SecurityKey1;
            var x509SecurityKey2 = KeyingMaterial.X509SecurityKey2;

            return new TheoryData<KeyMatchTheoryData>()
            {
                // Single Key
                new KeyMatchTheoryData
                {
                    First = true,
                    Kid = x509SecurityKey1.KeyId,
                    Match = x509SecurityKey1,
                    SecurityKey = x509SecurityKey1,
                    TestId = "KeyMatch1"
                },
                new KeyMatchTheoryData
                {
                    Match = x509SecurityKey1,
                    SecurityKey = x509SecurityKey1,
                    TestId = "KeyMatch3",
                    X5t = x509SecurityKey1.KeyId
                },
                new KeyMatchTheoryData
                {
                    Kid = x509SecurityKey1.X5t,
                    Match = x509SecurityKey1,
                    SecurityKey = x509SecurityKey1,
                    TestId = "KeyMatch3"
                },
                new KeyMatchTheoryData
                {
                    Match = x509SecurityKey1,
                    SecurityKey = x509SecurityKey1,
                    TestId = "KeyMatch4",
                    X5t = x509SecurityKey1.X5t
                },
                new KeyMatchTheoryData
                {
                    Kid = x509SecurityKey2.KeyId,
                    Match = x509SecurityKey2,
                    SecurityKeys = new Collection<SecurityKey>{ x509SecurityKey1, x509SecurityKey2 },
                    SecurityKey = x509SecurityKey1,
                    TestId = "KeyMatch5"
                },
                new KeyMatchTheoryData
                {
                    Match = x509SecurityKey2,
                    SecurityKeys = new Collection<SecurityKey>{ x509SecurityKey1, x509SecurityKey2 },
                    SecurityKey = x509SecurityKey1,
                    TestId = "KeyMatch6",
                    X5t = x509SecurityKey2.KeyId
                },
                new KeyMatchTheoryData
                {
                    Kid = x509SecurityKey2.X5t,
                    Match = x509SecurityKey2,
                    SecurityKeys = new Collection<SecurityKey>{ x509SecurityKey1, x509SecurityKey2 },
                    SecurityKey = x509SecurityKey1,
                    TestId = "KeyMatch7"
                },
                new KeyMatchTheoryData
                {
                    Match = x509SecurityKey2,
                    SecurityKeys = new Collection<SecurityKey>{ x509SecurityKey1, x509SecurityKey2 },
                    SecurityKey = x509SecurityKey1,
                    TestId = "KeyMatch8",
                    X5t = x509SecurityKey2.X5t
                },
                // no match
                new KeyMatchTheoryData
                {
                    Kid = x509SecurityKey2.KeyId,
                    SecurityKey = x509SecurityKey1,
                    TestId = "KeyMatch9",
                    X5t = x509SecurityKey2.X5t
                },
                new KeyMatchTheoryData
                {
                    Kid = x509SecurityKey1.KeyId,
                    SecurityKeys = new Collection<SecurityKey>{ x509SecurityKey2, x509SecurityKey2 },
                    TestId = "KeyMatch10",
                    X5t = x509SecurityKey1.KeyId
                },
                // null keys
                new KeyMatchTheoryData
                {
                    Match = null,
                    TestId = "KeyMatch11"
                },
                new KeyMatchTheoryData
                {
                    Kid = "Kid",
                    Match = null,
                    TestId = "KeyMatch12"
                },
                new KeyMatchTheoryData
                {
                    Kid = "Kid",
                    Match = null,
                    TestId = "KeyMatch13",
                    X5t = "X5t"
                },
                new KeyMatchTheoryData
                {
                    Kid = x509SecurityKey2.KeyId,
                    Match = null,
                    SecurityKey = null,
                    TestId = "KeyMatch14",
                    X5t = x509SecurityKey2.X5t
                },
                new KeyMatchTheoryData
                {
                    Kid = x509SecurityKey1.KeyId,
                    Match = null,
                    SecurityKeys = new Collection<SecurityKey>{ x509SecurityKey2, x509SecurityKey2 },
                    TestId = "KeyMatch15",
                    X5t = x509SecurityKey1.KeyId
                },
                new KeyMatchTheoryData
                {
                    Kid = x509SecurityKey1.KeyId,
                    Match = null,
                    SecurityKeys = new Collection<SecurityKey>{ null, x509SecurityKey2 },
                    TestId = "KeyMatch16",
                    X5t = x509SecurityKey1.KeyId
                }
            };
        }
    }

    public class KeyMatchTheoryData : TheoryDataBase
    {
        public string Kid { get; set; }

        public SecurityKey Match { get; set; }
        public SecurityKey SecurityKey { get; set; }

        public IEnumerable<SecurityKey> SecurityKeys { get; set; }
        
        public string X5t { get; set; }
    }
}
