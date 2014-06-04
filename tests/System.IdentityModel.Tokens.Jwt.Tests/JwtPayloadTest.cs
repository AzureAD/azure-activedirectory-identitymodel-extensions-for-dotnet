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
using System.Collections.Generic;
using System.IdentityModel.Claims;
using System.IdentityModel.Tokens;
using Claim = System.Security.Claims.Claim;

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
        [TestProperty("TestCaseID", "0B55BD6C-40F7-4C82-A0B7-D0B799EA3289")]
        [Description("Ensures that JwtPayload defaults are as expected")]
        public void JwtPayload_Defaults()
        {
            JwtPayload jwtPayload = new JwtPayload();

            Assert.AreEqual(jwtPayload.Comparer.GetType(), StringComparer.Ordinal.GetType(), "jwtPayload.Comparer.GetType() != StringComparer.Ordinal.GetType()");

            List<Claim> claims = jwtPayload.Claims as List<Claim>;
            Assert.IsNotNull(claims, "claims as List<Claim> == null");

            foreach (Claim c in jwtPayload.Claims)
            {
                Assert.Fail("claims should be null");
                break;
            }

            Assert.IsNull(jwtPayload.Actort, "jwtPayload.Actort != null");
            Assert.IsNull(jwtPayload.Aud, "jwtPayload.Audience != null");
            Assert.IsNull(jwtPayload.Exp, "jwtPayload.Exp != null");
            Assert.IsNull(jwtPayload.Jti, "jwtPayload.Id != null");
            Assert.IsNull(jwtPayload.Iat, "jwtPayload.Iat != null");
            Assert.IsNull(jwtPayload.Iss, "jwtPayload.Iss != null");
            Assert.IsNull(jwtPayload.Sub, "jwtPayload.Sub != null");
            Assert.AreEqual(jwtPayload.ValidFrom, DateTime.MinValue, "jwtPayload.ValidFrom != DateTime.MinValue");
            Assert.AreEqual(jwtPayload.ValidTo, DateTime.MinValue, "jwtPayload.ValidTo != DateTime.MinValue");
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

            Assert.AreEqual(EpochTime.DateTime(time.Value), jwtPayload.ValidTo, "EpochTime.DateTime( time ) != jwtPayload.ValidTo");

            int? expirationTime = jwtPayload.Exp;
            Assert.AreEqual(expirationTime, time, "expirationTime != time");
        }
    }
}