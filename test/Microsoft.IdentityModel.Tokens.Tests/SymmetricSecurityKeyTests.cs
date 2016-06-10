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
using Xunit;

namespace Microsoft.IdentityModel.Tokens.Tests
{
    public class SymmetricSecurityKeyTests
    {

#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant
        [Theory, MemberData("ConstructorDataSet")]
#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant        
        public void Constructor(byte[] key, ExpectedException ee)
        {
            try
            {
                var symmetricSecurityKey = new SymmetricSecurityKey(key);
                ee.ProcessNoException();
            }
            catch (Exception exception)
            {
                ee.ProcessException(exception);
            }
        }

        public static TheoryData<byte[], ExpectedException> ConstructorDataSet
        {
            get
            {
                var dataset = new TheoryData<byte[], ExpectedException>();
                dataset.Add(KeyingMaterial.DefaultSymmetricKeyBytes_256, ExpectedException.NoExceptionExpected);
                dataset.Add(null, ExpectedException.ArgumentNullException());
                dataset.Add(new byte[0], ExpectedException.ArgumentException());
                return dataset;
            }
        }

#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant
        [Theory, MemberData("IsSupportedAlgDataSet")]
#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
        public void IsSupportedAlgorithm(SymmetricSecurityKey key, string alg, bool expectedResult)
        {
            if (key.IsSupportedAlgorithm(alg) != expectedResult)
                Assert.True(false, string.Format("{0} failed with alg: {1}. ExpectedResult: {2}", key, alg, expectedResult));
        }

        public static TheoryData<SymmetricSecurityKey, string, bool> IsSupportedAlgDataSet
        {
            get
            {
                var dataset = new TheoryData<SymmetricSecurityKey, string, bool>();
                dataset.Add(KeyingMaterial.DefaultSymmetricSecurityKey_256, SecurityAlgorithms.HmacSha256, true);
                dataset.Add(KeyingMaterial.SymmetricSecurityKey2_256, SecurityAlgorithms.HmacSha384Signature, true);
                dataset.Add(KeyingMaterial.DefaultSymmetricSecurityKey_256, SecurityAlgorithms.Aes128Encryption, false);

                SymmetricSecurityKey testKey = new SymmetricSecurityKey(KeyingMaterial.DefaultSymmetricKeyBytes_256);
                testKey.CryptoProviderFactory = new CustomCryptoProviderFactory(new string[] { SecurityAlgorithms.Aes128Encryption });
                dataset.Add(testKey, SecurityAlgorithms.Aes128Encryption, true);
                return dataset;
            }
        }
    }
}