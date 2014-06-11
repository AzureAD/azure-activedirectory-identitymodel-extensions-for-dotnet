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
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Collections.Generic;
using System.IdentityModel.Tokens;
using System.Reflection;
using System.Text;
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
                Assert.Fail("jwtPayload.Claims should be empty");
            }

            Assert.IsNotNull(jwtPayload.Aud, "jwtPayload.Aud should not be null");
            foreach(string audience in jwtPayload.Aud)
            {
                Assert.Fail("jwtPayload.Aud should be empty");
            }

            Assert.AreEqual(jwtPayload.ValidFrom, DateTime.MinValue, "jwtPayload.ValidFrom != DateTime.MinValue");
            Assert.AreEqual(jwtPayload.ValidTo, DateTime.MinValue, "jwtPayload.ValidTo != DateTime.MinValue");
        }

        [TestMethod]
        [TestProperty("TestCaseID", "DB01AD64-AB08-4AD6-ACE9-197878AAD9B6")]
        [Description("Tests: GetSets, covers defaults")]
        public void JwtPayload_GetSets()
        {
            // Aud, Claims, ValidFrom, ValidTo handled in Defaults.

            JwtPayload jwtPayload = new JwtPayload();
            Type type = typeof(JwtPayload);
            PropertyInfo[] properties = type.GetProperties();
            if (properties.Length != 19)
                Assert.Fail("Number of properties has changed from 19 to: " + properties.Length + ", adjust tests");

            GetSetContext context =
                new GetSetContext
                {
                    PropertyNamesAndSetGetValue = new List<KeyValuePair<string, List<object>>> 
                    { 
                        new KeyValuePair<string, List<object>>("Actort", new List<object>{(string)null, Guid.NewGuid().ToString(), Guid.NewGuid().ToString()}),
                        new KeyValuePair<string, List<object>>("Acr", new List<object>{(string)null, Guid.NewGuid().ToString(), Guid.NewGuid().ToString()}),
                        new KeyValuePair<string, List<object>>("Amr", new List<object>{(string)null, Guid.NewGuid().ToString(), Guid.NewGuid().ToString()}),
                        new KeyValuePair<string, List<object>>("AuthTime", new List<object>{(string)null, Guid.NewGuid().ToString(), Guid.NewGuid().ToString()}),
                        new KeyValuePair<string, List<object>>("Azp", new List<object>{(string)null, Guid.NewGuid().ToString(), Guid.NewGuid().ToString()}),
                        new KeyValuePair<string, List<object>>("CHash", new List<object>{(string)null, Guid.NewGuid().ToString(), Guid.NewGuid().ToString()}),
                        new KeyValuePair<string, List<object>>("Exp", new List<object>{(string)null, 1, 0 }),
                        new KeyValuePair<string, List<object>>("Jti", new List<object>{(string)null, Guid.NewGuid().ToString(), Guid.NewGuid().ToString()}),
                        new KeyValuePair<string, List<object>>("Iat", new List<object>{(string)null, 10, 0}),
                        new KeyValuePair<string, List<object>>("Iss", new List<object>{(string)null, Guid.NewGuid().ToString(), Guid.NewGuid().ToString()}),
                        new KeyValuePair<string, List<object>>("Nonce", new List<object>{(string)null, Guid.NewGuid().ToString(), Guid.NewGuid().ToString()}),
                        new KeyValuePair<string, List<object>>("Sub", new List<object>{(string)null, Guid.NewGuid().ToString(), Guid.NewGuid().ToString()}),
                    },
                    Object = jwtPayload,
                };
            TestUtilities.GetSet(context);

            if (context.Errors.Count != 0)
            {
                StringBuilder sb = new StringBuilder();
                sb.AppendLine(Environment.NewLine);
                foreach (string str in context.Errors)
                    sb.AppendLine(str);

                Assert.Fail(sb.ToString());
            }


        }

        [TestMethod]
        [TestProperty( "TestCaseID", "4D8369F1-8846-41C2-89C9-3827955032A6" )]
        [Description( "Test claims as objects" )]
        public void JwtPalyoad_Claims()
        {
            JwtPayload jwtPayload = new JwtPayload();
            // multiple audiences

            jwtPayload.Add(JwtRegisteredClaimNames.Aud, IdentityUtilities.DefaultAudiences);
            string encodedPayload = jwtPayload.Encode();
            JwtPayload newjwtPayload = Base64UrlEncoder.Decode(encodedPayload).DeserializeJwtPayload();

            Assert.IsTrue(IdentityComparer.AreEqual(jwtPayload, newjwtPayload));

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