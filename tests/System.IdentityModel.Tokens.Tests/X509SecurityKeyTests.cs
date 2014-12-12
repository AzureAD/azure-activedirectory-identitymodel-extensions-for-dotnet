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

using Microsoft.IdentityModel.Test;
using Xunit;
using System.IdentityModel.Tokens;
using System.Security.Cryptography.X509Certificates;

namespace System.IdentityModel.Test
{
    public class X509SecurityKeyTests
    {
        [Fact(DisplayName = "Tests: Constructor")]
        public void X509SecurityKey_Constructor()
        {
            X509SecurityKey x509SecurityKey;
            ExpectedException expectedException = new ExpectedException(typeExpected: typeof(ArgumentNullException), substringExpected: "certificate");
            try
            {
                x509SecurityKey = new X509SecurityKey(null);
                expectedException.ProcessNoException();
            }
            catch(Exception exception)
            {
                expectedException.ProcessException(exception);
            }

            X509Certificate2 x509Certificate2 = KeyingMaterial.DefaultCert_2048;
            expectedException = ExpectedException.NoExceptionExpected;
            try
            {
                x509SecurityKey = new X509SecurityKey(x509Certificate2);
                Assert.Same(x509Certificate2, x509SecurityKey.Certificate);
            }
            catch (Exception exception)
            {
                expectedException.ProcessException(exception);
            }
        }

        [Fact(DisplayName = "Tests: Defaults")]
        public void X509SecurityKey_Defaults()
        {
            // there are no defaults.
        }
    }
}
