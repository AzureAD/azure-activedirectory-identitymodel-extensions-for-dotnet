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

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Xunit;

namespace System.IdentityModel.Tokens.Tests
{
    public class ECDsaSecurityKeyTests
    {
        [Fact(DisplayName = "ECDsaSecurityKeyTests: Constructor")]
        public void Constructor()
        {
            // null blob
            ECDsaSecurityKeyConstructor(null, null, new ExpectedException(typeof(ArgumentNullException), "blob"));
            byte[] ecdsa256KeyBlob = TestUtilities.HexToByteArray("454353322000000096e476f7473cb17c5b38684daae437277ae1efadceb380fad3d7072be2ffe5f0b54a94c2d6951f073bfc25e7b81ac2a4c41317904929d167c3dfc99122175a9438e5fb3e7625493138d4149c9438f91a2fecc7f48f804a92b6363776892ee134");
            // null blob format
            ECDsaSecurityKeyConstructor(ecdsa256KeyBlob, null, new ExpectedException(typeof(ArgumentNullException), "blobFormat"));
            ECDsaSecurityKeyConstructor(ecdsa256KeyBlob, CngKeyBlobFormat.GenericPrivateBlob, ExpectedException.NoExceptionExpected);

            var ecdsaSecurityKey = new ECDsaSecurityKey(ecdsa256KeyBlob, CngKeyBlobFormat.GenericPrivateBlob);
            Assert.True(ecdsaSecurityKey.HasPrivateKey, "ecdsaSecurityKey.HasPrivate is false");
        }

        private void ECDsaSecurityKeyConstructor(byte[] blob, CngKeyBlobFormat format, ExpectedException ee)
        {
            try
            {
                var ecdsaSecurityKey = new ECDsaSecurityKey(blob, format);
                ee.ProcessNoException();
            }
            catch (Exception exception)
            {
                ee.ProcessException(exception);
            }
        }

        [Fact(DisplayName = "ECDsaSecurityKeyTests: Defaults")]
        public void Defaults()
        {
            // there are no defaults.
        }
    }
}
