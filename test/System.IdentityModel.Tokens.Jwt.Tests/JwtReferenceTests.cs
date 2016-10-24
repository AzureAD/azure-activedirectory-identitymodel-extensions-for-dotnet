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

using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Tokens.Tests;
using Xunit;

namespace System.IdentityModel.Tokens.Jwt.Tests
{
    /// <summary>
    /// 
    /// </summary>
    public class JwtReferenceTests
    {
#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant
        [Theory, MemberData("Base64UrlEncodingTheoryData")]
#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant

        public void Base64UrlEncoding(string testId, string dataToEncode, string encodedData)
        {
            Assert.True(dataToEncode.Equals(Base64UrlEncoder.Decode(encodedData), StringComparison.Ordinal), "dataToEncode.Equals(Base64UrlEncoder.Decode(encodedData), StringComparison.Ordinal)");
            Assert.True(encodedData.Equals(Base64UrlEncoder.Encode(dataToEncode), StringComparison.Ordinal), "encodedData.Equals(Base64UrlEncoder.Encode(dataToEncode), StringComparison.Ordinal)");
        }

        public static TheoryData<string, string, string> Base64UrlEncodingTheoryData
        {
            get
            {
                var theoryData = new TheoryData<string, string, string>();

                theoryData.Add("Test1", RFC7520References.Payload, RFC7520References.PayloadEncoded);
                theoryData.Add("Test2", RFC7520References.RSAHeader, RFC7520References.RSAHeaderEncoded);
                theoryData.Add("Test3", RFC7520References.ES512Header, RFC7520References.ES512Encoded);
                theoryData.Add("Test4", RFC7520References.SymmetricHeader, RFC7520References.SymmetricHeaderEncoded);

                return theoryData;
            }
        }

#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant
        [Theory, MemberData("JwtEncodingTheoryData")]
#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
        public void JwtEncoding(string testId, JwtHeader header, string encodedData)
        {
            Assert.True(encodedData.Equals(header.Base64UrlEncode(), StringComparison.Ordinal), "encodedData.Equals(header.Base64UrlEncode(), StringComparison.Ordinal)");
        }

        public static TheoryData<string, object, string> JwtEncodingTheoryData
        {
            get
            {
                var theoryData = new TheoryData<string, object, string>();

                theoryData.Add("Test1", RFC7520References.ES512JwtHeader, RFC7520References.ES512Encoded);
                theoryData.Add("Test2", RFC7520References.RSAJwtHeader, RFC7520References.RSAHeaderEncoded);
                theoryData.Add("Test3", RFC7520References.SymmetricJwtHeader, RFC7520References.SymmetricHeaderEncoded);

                return theoryData;
            }
        }
    }
}
