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

using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.IdentityModel.Tokens;
using System.Security.Cryptography.X509Certificates;

namespace System.IdentityModel.Test
{
    [TestClass]
    public class X509SecurityKeyTests
    {
                /// <summary>
        /// Test Context Wrapper instance on top of TestContext. Provides better accessor functions
        /// </summary>
        protected TestContextProvider _testContextProvider;

        public TestContext TestContext { get; set; }

        [ClassInitialize]
        public static void ClassSetup( TestContext testContext )
        {}

        [ClassCleanup]
        public static void ClassCleanup()
        {}

        [TestInitialize]
        public void Initialize()
        {
            _testContextProvider = new TestContextProvider( TestContext );
        }

        [TestMethod]
        [TestProperty("TestCaseID", "7884A13A-0DEE-4EB8-87F5-BDD4226B32FD")]
        [Description("Tests: Constructor")]
        public void X509SecurityKey_Constructor()
        {
            X509SecurityKey x509SecurityKey;
            ExpectedException expectedException = new ExpectedException(thrown: typeof(ArgumentNullException), id: "certificate");
            try
            {
                x509SecurityKey = new X509SecurityKey(null);
                ExpectedException.ProcessNoException(expectedException);
            }
            catch(Exception exception)
            {
                ExpectedException.ProcessException(expectedException, exception);
            }

            X509Certificate2 x509Certificate2 = KeyingMaterial.Cert_2048;
            expectedException = ExpectedException.Null;
            try
            {
                x509SecurityKey = new X509SecurityKey(x509Certificate2);
                Assert.ReferenceEquals(x509Certificate2, x509SecurityKey.Certificate);
            }
            catch (Exception exception)
            {
                ExpectedException.ProcessException(expectedException, exception);
            }
        }

        [TestMethod]
        [TestProperty("TestCaseID", "227AC92B-16D3-47A8-AD47-0F49D0157D6D")]
        [Description("Tests: Defaults")]
        public void X509SecurityKey_Defaults()
        {
            // there are no defaults.
        }
    }
}
