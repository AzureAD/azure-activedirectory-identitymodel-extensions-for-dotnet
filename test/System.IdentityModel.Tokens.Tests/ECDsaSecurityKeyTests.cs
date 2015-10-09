//-----------------------------------------------------------------------
// Copyright (c) Microsoft Open Technologies, Inc.
// All Rights Reserved
// Apache License 2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// 
// http://www.apache.org/licenses/LICENSE-2.0
// 
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//-----------------------------------------------------------------------

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
            ECDsaSecurityKeyConstructor(null, null, new ExpectedException(typeof(ArgumentNullException), "ECDsaSecurityKey.blob"));
            byte[] ecdsa256KeyBlob = TestUtilities.HexToByteArray("454353322000000096e476f7473cb17c5b38684daae437277ae1efadceb380fad3d7072be2ffe5f0b54a94c2d6951f073bfc25e7b81ac2a4c41317904929d167c3dfc99122175a9438e5fb3e7625493138d4149c9438f91a2fecc7f48f804a92b6363776892ee134");
            ECDsaSecurityKeyConstructor(ecdsa256KeyBlob, null, new ExpectedException(typeof(ArgumentNullException), "ECDsaSecurityKey.blobFormat"));
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
