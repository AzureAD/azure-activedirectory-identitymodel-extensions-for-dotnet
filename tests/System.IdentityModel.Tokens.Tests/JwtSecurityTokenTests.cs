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
using Xunit;
using Claim = System.Security.Claims.Claim;

namespace System.IdentityModel.Test
{
    public class JwtSecurityTokenTests
    {
        [Fact( DisplayName = "JwtSecurityTokenTests: Defaults")]
        public void Defaults()
        {
            JwtSecurityToken jwt = new JwtSecurityToken();

            List<Claim> claims = jwt.Claims as List<Claim>;
            Assert.NotNull(claims);

            foreach (Claim c in jwt.Claims)
            {
                Assert.True(false, "claims.Count != 0");
                break;
            }

            Assert.Null(jwt.Actor);
            Assert.NotNull(jwt.Audiences);
            foreach (string aud in jwt.Audiences)
            {
                Assert.True(false, "jwt.Audiences should be empty");
            }
            Assert.Null(jwt.Id);
            Assert.Null(jwt.Issuer);
            Assert.Null(jwt.SecurityKey);
            Assert.NotNull(jwt.SignatureAlgorithm);
            Assert.Equal(jwt.SignatureAlgorithm, "none");
            Assert.Null(jwt.SigningCredentials);
            Assert.Null(jwt.SigningKey);
            Assert.Null(jwt.Subject);
            Assert.Equal(jwt.ValidFrom, DateTime.MinValue);
            Assert.Equal(jwt.ValidTo, DateTime.MinValue);
            Assert.Null(jwt.RawData);
            Assert.NotNull(jwt.Header);
            Assert.NotNull(jwt.Payload);
            Assert.NotNull(jwt.EncodedHeader);
            Assert.NotNull(jwt.EncodedPayload);
        }

        [Fact( DisplayName = "JwtSecurityTokenTests: Constructor using encoded string.")]
        public void EncodedStringConstruction()
        {
            Console.WriteLine("Entering: JwtSecurityToken_EncodedStringConstruction");
            string[] tokenParts = EncodedJwts.Asymmetric_LocalSts.Split('.');

            RunEncodedTest(new JwtSecurityTokenTestVariation
            {
                Name = "EncodedString: OverClaims",
                EncodedString = EncodedJwts.OverClaims,
                ExpectedException = ExpectedException.NoExceptionExpected,
            });


            RunEncodedTest(new JwtSecurityTokenTestVariation
            {
                Name = "EncodedString: InvalidPayloadFormat",
                EncodedString = EncodedJwts.InvalidPayload,
                ExpectedException = ExpectedException.ArgumentException(substringExpected: "IDX10703:", inner: typeof(FormatException)),
            });

            RunEncodedTest(new JwtSecurityTokenTestVariation
            {
                Name = "EncodedString: null",
                EncodedString = null,
                ExpectedException = ExpectedException.ArgumentNullException(),
            });

            RunEncodedTest(new JwtSecurityTokenTestVariation
            {
                Name = "EncodedString: string.Empty",
                EncodedString = string.Empty,
                ExpectedException = ExpectedException.ArgumentException(substringExpected: "IDX10002:"),
            });

            RunEncodedTest(new JwtSecurityTokenTestVariation
            {
                Name = "EncodedString: single character: '1'",
                EncodedString = "1",
                ExpectedException = ExpectedException.ArgumentException(substringExpected: "IDX10709:"),
            });

            RunEncodedTest(new JwtSecurityTokenTestVariation
            {
                Name = "EncodedString: two parts each a single character: '1.2'",
                EncodedString = "1.2",
                ExpectedException = ExpectedException.ArgumentException(substringExpected: "IDX10709:"),
            });

            RunEncodedTest(new JwtSecurityTokenTestVariation
            {
                Name = "EncodedString: header is not encoded properly: '123'",
                EncodedString = string.Format("{0}.{1}.{2}", "123", tokenParts[1], tokenParts[2]),
                ExpectedException = ExpectedException.ArgumentException(substringExpected: "IDX10703:", inner: typeof(Newtonsoft.Json.JsonReaderException)),
            });

            RunEncodedTest(new JwtSecurityTokenTestVariation
            {
                Name = "EncodedString: header is not encoded properly: '123=='",
                EncodedString = string.Format("{0}.{1}.{2}", "123==", tokenParts[1], tokenParts[2]),
                ExpectedException = ExpectedException.ArgumentException(substringExpected: "IDX10709"),
            });

            RunEncodedTest(new JwtSecurityTokenTestVariation
            {
                Name = "EncodedString: payload is not encoded correctly: '123'",
                EncodedString = string.Format("{1}.{0}.{2}", "123", tokenParts[0], tokenParts[2]),
                ExpectedException = ExpectedException.ArgumentException(substringExpected: "IDX10703:", inner: typeof(Newtonsoft.Json.JsonReaderException)),
            });

            RunEncodedTest(new JwtSecurityTokenTestVariation
            {
                Name = "EncodedString: payload is not encoded properly: '123=='",
                EncodedString = string.Format("{1}.{0}.{2}", "123==", tokenParts[0], tokenParts[2]),
                ExpectedException = ExpectedException.ArgumentException(substringExpected: "IDX10709:"),
            });

            RunEncodedTest(new JwtSecurityTokenTestVariation
            {
                Name = "EncodedString: valid encoding, NO signature (JWT_AsymmetricSigned_AcsV2)",
                EncodedString = string.Format("{0}.{1}.", tokenParts[0], tokenParts[1]),
                ExpectedException = ExpectedException.NoExceptionExpected,
            });

            RunEncodedTest(new JwtSecurityTokenTestVariation
            {
                Name = "EncodedString: valid encoding, NO signature (JWT_AsymmetricSigned_AcsV2)",
                EncodedString = string.Format("{0}.{1}.{2}.{3}", tokenParts[0], tokenParts[1], tokenParts[2], tokenParts[2]),
                ExpectedException = ExpectedException.ArgumentException(substringExpected: "IDX10709:"),
            });
        }

        private void RunEncodedTest(JwtSecurityTokenTestVariation variation)
        {
            JwtSecurityToken jwt = null;
            Console.WriteLine(string.Format("Variation: {0}", variation.Name));
            try
            {
                jwt = new JwtSecurityToken(variation.EncodedString);
                IEnumerable<Claim> claims = jwt.Payload.Claims;
                variation.ExpectedException.ProcessNoException();
            }
            catch (Exception ex)
            {
                variation.ExpectedException.ProcessException(ex);
            }

            // ensure we can get to every property
            if (jwt != null && (variation.ExpectedException == null || variation.ExpectedException.TypeExpected == null))
            {
                TestUtilities.CallAllPublicInstanceAndStaticPropertyGets(jwt, variation.Name);
            }

            if (null != variation.ExpectedJwtSecurityToken)
            {
                Assert.True(
                    IdentityComparer.AreEqual(variation.ExpectedJwtSecurityToken, jwt),
                    string.Format("Testcase: {0}.  JWTSecurityTokens are not equal.", variation.Name));
            }
        }

        [Fact( DisplayName = "JwtSecurityTokenTests:: Constructors")]
        public void Constructors()
        {
            Console.WriteLine("Entering: JwtSecurityToken_Constructor");
            RunConstructionTest(
                new JwtSecurityTokenTestVariation
                {
                    Name = "ClaimsSet with all Reserved claim types, ensures that users can add as they see fit",
                    Claims = ClaimSets.AllReserved,
                    ExpectedException = ExpectedException.NoExceptionExpected,
                });

            RunConstructionTest(
                new JwtSecurityTokenTestVariation
                {
                    Name = "All null params",
                    Issuer = null,
                    Audience = null,
                    Claims = null,
                    SigningCredentials = null,
                    ExpectedException = ExpectedException.NoExceptionExpected,
                });

            RunConstructionTest(
                new JwtSecurityTokenTestVariation
                {
                    Name = "NotBefore > Expires, .Net datetime",
                    NotBefore = DateTime.UtcNow + TimeSpan.FromHours(1),
                    Expires = DateTime.UtcNow,
                    ExpectedException = ExpectedException.ArgumentException(substringExpected: "IDX10401"),
                });

            RunConstructionTest(
                new JwtSecurityTokenTestVariation
                {
                    Name = "NotBefore > Expires, UnixEpoch - 1 ms",
                    NotBefore = DateTime.UtcNow,
                    Expires = EpochTime.UnixEpoch - TimeSpan.FromMilliseconds(1),
                    ExpectedException = ExpectedException.ArgumentException(substringExpected: "IDX10401"),
                });

            RunConstructionTest(
                new JwtSecurityTokenTestVariation
                {
                    Name = "NotBefore > Expires, UnixEpoch - 1 s",
                    NotBefore = DateTime.UtcNow,
                    Expires = EpochTime.UnixEpoch - TimeSpan.FromSeconds(1),
                    ExpectedException = ExpectedException.ArgumentException(substringExpected: "IDX10401"),
                });

            RunConstructionTest(
                new JwtSecurityTokenTestVariation
                {
                    Name = "NotBefore == DateItime.MinValue",
                    NotBefore = DateTime.MinValue,
                    Expires = DateTime.UtcNow,
                });
        }

        private void RunConstructionTest(JwtSecurityTokenTestVariation variation)
        {
            JwtSecurityToken jwt = null;
            try
            {
                jwt = new JwtSecurityToken(
                    issuer: variation.Issuer,
                    audience: variation.Audience,
                    claims: variation.Claims,
                    signingCredentials: variation.SigningCredentials,
                    notBefore: variation.NotBefore,
                    expires: variation.Expires);

                variation.ExpectedException.ProcessNoException();
            }
            catch (Exception ex)
            {
                variation.ExpectedException.ProcessException(ex);
            }

            try
            {
                // ensure we can get to every property
                if (jwt != null && (variation.ExpectedException == null || variation.ExpectedException.TypeExpected == null))
                {
                    TestUtilities.CallAllPublicInstanceAndStaticPropertyGets(jwt, variation.Name);
                }

                if (null != variation.ExpectedJwtSecurityToken)
                {
                    Assert.True(IdentityComparer.AreEqual(variation.ExpectedJwtSecurityToken, jwt));
                }
            }
            catch (Exception ex)
            {
                Assert.True(false, string.Format("Testcase: {0}. UnExpected when getting a properties: '{1}'", variation.Name, ex.ToString()));
            }
        }
    }
}
