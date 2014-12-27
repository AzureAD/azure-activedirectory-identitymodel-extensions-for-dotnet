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

using System.Collections.Generic;
using System.IdentityModel.Tokens;
using System.Reflection;
using System.Text;
using Xunit;

using Claim = System.Security.Claims.Claim;

namespace System.IdentityModel.Test
{
    public class JwtPayloadTests
    {
        /// <summary>
        /// Test Context Wrapper instance on top of TestContext. Provides better accessor functions
        /// </summary>
        [Fact(DisplayName = "JwtPayloadTests: Ensures that JwtPayload defaults are as expected")]
        public void Defaults()
        {
            JwtPayload jwtPayload = new JwtPayload();
            List<Claim> claims = jwtPayload.Claims as List<Claim>;
            Assert.True(claims != null, "claims as List<Claim> == null");

            foreach (Claim c in jwtPayload.Claims)
            {
                Assert.True(false, "jwtPayload.Claims should be empty");
            }

            Assert.True(jwtPayload.Aud != null, "jwtPayload.Aud should not be null");
            foreach(string audience in jwtPayload.Aud)
            {
                Assert.True(false, "jwtPayload.Aud should be empty");
            }

            Assert.True(jwtPayload.ValidFrom == DateTime.MinValue, "jwtPayload.ValidFrom != DateTime.MinValue");
            Assert.True(jwtPayload.ValidTo == DateTime.MinValue, "jwtPayload.ValidTo != DateTime.MinValue");
        }

        [Fact(DisplayName = "JwtPayloadTests: GetSets, covers defaults")]
        public void GetSets()
        {
            // Aud, Claims, ValidFrom, ValidTo handled in Defaults.

            JwtPayload jwtPayload = new JwtPayload();
            Type type = typeof(JwtPayload);
            PropertyInfo[] properties = type.GetProperties();
            if (properties.Length != 22)
                Assert.True(false,"Number of properties has changed from 22 to: " + properties.Length + ", adjust tests");

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
                        new KeyValuePair<string, List<object>>("Nbf", new List<object>{(string)null, 1, 0 }),
                        new KeyValuePair<string, List<object>>("Nonce", new List<object>{(string)null, Guid.NewGuid().ToString(), Guid.NewGuid().ToString()}),
                        new KeyValuePair<string, List<object>>("Sub", new List<object>{(string)null, Guid.NewGuid().ToString(), Guid.NewGuid().ToString()}),
                    },
                    Object = jwtPayload,
                };
            TestUtilities.GetSet(context);
            TestUtilities.AssertFailIfErrors("JwtPayload_GetSets", context.Errors);
        }

        [Fact(DisplayName = "JwtPayloadTests: Claims as objects")]
        public void Claims()
        {
            List<string> errors = new List<string>();
            var jwtPayload = new JwtPayload();
    
            // multiple audiences
            foreach (string aud in IdentityUtilities.DefaultAudiences)
            {
                jwtPayload.AddClaim(new Claim(JwtRegisteredClaimNames.Aud, aud));
            }

            string encodedPayload = jwtPayload.Base64UrlEncode();
            var deserializedPayload = JwtPayload.Base64UrlDeserialize(encodedPayload);

            if (!IdentityComparer.AreEqual(jwtPayload, deserializedPayload))
            {
                errors.Add("!IdentityComparer.AreEqual(jwtPayload, deserializedPayload)");
            }

            if (!IdentityComparer.AreEqual<IEnumerable<string>>(jwtPayload.Aud, IdentityUtilities.DefaultAudiences))
            {
                errors.Add("!IdentityComparer.AreEqual<IEnumerable<string>>(jwtPayload.Aud, IdentityUtilities.DefaultAudiences)");
            }

            TestUtilities.AssertFailIfErrors("JwtPalyoad_Claims", errors);
        }

        [Fact(DisplayName = "JwtPayloadTests: Adding non-strings as 'exp'")]
        public void ObjectClaims()
        {
            JwtPayload jwtPayload = new JwtPayload();
            int? time = 10000;
            jwtPayload.Add("exp", time );
            DateTime payloadTime = EpochTime.DateTime( time.Value );
            DateTime payloadValidTo = jwtPayload.ValidTo;

            Assert.True(EpochTime.DateTime(time.Value) == jwtPayload.ValidTo, "EpochTime.DateTime( time ) != jwtPayload.ValidTo");

            int? expirationTime = jwtPayload.Exp;
            Assert.True(expirationTime == time, "expirationTime != time");
        }
    }
}