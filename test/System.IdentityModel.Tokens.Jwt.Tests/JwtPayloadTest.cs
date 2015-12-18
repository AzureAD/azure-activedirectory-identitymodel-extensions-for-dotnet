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

using System.Collections.Generic;
using System.Reflection;
using System.Security.Claims;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Tokens.Tests;
using Xunit;

namespace System.IdentityModel.Tokens.Jwt.Tests
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

            Assert.True(jwtPayload.Amr != null, "jwtPayload.Amr should not be null");
            foreach (string audience in jwtPayload.Amr)
            {
                Assert.True(false, "jwtPayload.Amr should be empty");
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
                        new KeyValuePair<string, List<object>>("AuthTime", new List<object>{(string)null, 10, 12 }),
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

            // multiple amrs
            var amrs = new Newtonsoft.Json.Linq.JArray("amr1", "amr2", "amr3");
            foreach (var amr in amrs)
            {
                jwtPayload.AddClaim(new Claim(JwtRegisteredClaimNames.Amr, amr.ToString()));
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

            if (!IdentityComparer.AreEqual<IEnumerable<string>>(jwtPayload.Amr, amrs.ToObject<List<string>>()))
            {
                errors.Add("!IdentityComparer.AreEqual<IEnumerable<string>>(jwtPayload.Amr, amrs)");
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

        [Fact(DisplayName = "JwtPayloadTests: test claim with null value")]
        public void TestClaimWithNullValue()
        {
            JwtPayload jwtPayload = new JwtPayload();
            jwtPayload.Add("testClaim", null);
            List<Claim> claims = jwtPayload.Claims as List<Claim>;   // this should not throw
        }
    }
}
