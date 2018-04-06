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
using System.Security.Cryptography.X509Certificates;
using Microsoft.IdentityModel.Tests;
using Xunit;

#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant

namespace Microsoft.IdentityModel.Tokens.Tests
{
    public class JsonWebKeyConverterTest
    {
        [Theory, MemberData(nameof(JsonWebKeyConverterTestTheoryData))]
        public void ConverterTest(ConverterTheoryData theoryData)
        {
            TestUtilities.WriteHeader($"{this}.ConverterTest", theoryData);
            var context = new CompareContext($"{this}.ConverterTest, {theoryData.TestId}");

            try
            {
                var jsonWebKey = JsonWebKeyConverter.ConvertFromSecurityKey(theoryData.SecurityKey);
                if (theoryData.SecurityKey.GetType() == typeof(X509SecurityKey))
                {
                    theoryData.ExpectedException.ProcessNoException(context);
                    IdentityComparer.AreEqual(jsonWebKey.Kty, theoryData.ComparisonJsonWebKey.Kty, context);
                    IdentityComparer.AreEqual(jsonWebKey.Kid, theoryData.ComparisonJsonWebKey.Kid, context);
                    var certificateExpected = (theoryData.SecurityKey as X509SecurityKey).Certificate;
                    var certificateNew = new X509Certificate2(Convert.FromBase64String(jsonWebKey.X5c[0]));
                    IdentityComparer.AreEqual(certificateNew, certificateExpected, context);
                }
                else
                {
                    theoryData.ExpectedException.ProcessNoException(context);
                    IdentityComparer.AreEqual(jsonWebKey, theoryData.ComparisonJsonWebKey, context);
                }
            }
            catch(Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<ConverterTheoryData> JsonWebKeyConverterTestTheoryData
        {
            get
            {
                return new TheoryData<ConverterTheoryData>()
                {
                    new ConverterTheoryData
                    {
                        First = true,
                        SecurityKey = KeyingMaterial.RsaSecurityKey_2048,
                        ComparisonJsonWebKey = KeyingMaterial.JsonWebKeyRsa256,
                        TestId = nameof(KeyingMaterial.RsaSecurityKey_2048)
                    },
                    new ConverterTheoryData
                    {
                        SecurityKey = KeyingMaterial.RsaSecurityKey_2048_Public,
                        ComparisonJsonWebKey = KeyingMaterial.JsonWebKeyRsa256Public,
                        TestId = nameof(KeyingMaterial.RsaSecurityKey_2048_Public)
                    },
                    new ConverterTheoryData
                    {
                        SecurityKey = KeyingMaterial.DefaultSymmetricSecurityKey_64,
                        ComparisonJsonWebKey = KeyingMaterial.JsonWebKeySymmetric64,
                        TestId = nameof(KeyingMaterial.DefaultSymmetricSecurityKey_64)
                    },
                    new ConverterTheoryData
                    {
                        SecurityKey = KeyingMaterial.DefaultX509Key_2048_With_KeyId,
                        ComparisonJsonWebKey = KeyingMaterial.JsonWebKeyX509_2048,
                        TestId = nameof(KeyingMaterial.DefaultX509Key_2048_With_KeyId)
                    },
                    new ConverterTheoryData
                    {
                        SecurityKey = KeyingMaterial.Ecdsa256Key,
                        ExpectedException = ExpectedException.NotSupportedException("IDX10674"),
                        TestId = "Security key not supported test"
                    },
                };
            }
        }
    }

    public class ConverterTheoryData : TheoryDataBase
    {
        public SecurityKey SecurityKey
        {
            get;
            set;
        }
        public JsonWebKey ComparisonJsonWebKey
        {
            get;
            set;
        }
    }
}

#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
