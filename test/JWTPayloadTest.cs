// ----------------------------------------------------------------------------------
//
// Copyright Microsoft Corporation
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
// ----------------------------------------------------------------------------------

using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.IdentityModel.Tokens;

namespace System.IdentityModel.Test
{
    [TestClass]
    public class JwtPayloadTests
    {
        /// <summary>
        /// Test Context Wrapper instance on top of TestContext. Provides better accessor functions
        /// </summary>
        protected TestContextProvider _testContextProvider;


        public TestContext TestContext { get; set; }


        [ClassInitialize]
        public static void ClassSetup( TestContext testContext )
        {
        }

        [ClassCleanup]
        public static void ClassCleanup()
        {
        }

        [TestInitialize]
        public void Initialize()
        {
            _testContextProvider = new TestContextProvider( TestContext );
        }

        [TestMethod]
        [TestProperty( "TestCaseID", "F443747C-5AA1-406D-B0FE-53152CA92DA3" )]
        [Description( "Tests adding non-strings as 'exp'" )]
        public void JwtPalyoad_ObjectClaims()
        {
            JwtPayload jwtPayload = new JwtPayload();
            int? time = 10000;
            jwtPayload.Add( "exp", time );
            DateTime payloadTime = EpochTime.DateTime( time.Value );
            DateTime payloadValidTo = jwtPayload.ValidTo;

            Assert.IsFalse(EpochTime.DateTime(time.Value) != jwtPayload.ValidTo, "EpochTime.DateTime( time ) != jwtPayload.ValidTo");

            int? expirationTime = jwtPayload.Expiration;
            Assert.IsTrue(expirationTime == time, "expirationTime != time");
        }
    }
}