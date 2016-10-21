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
using System.Security.Claims;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Tokens.Tests;
using Xunit;

namespace System.IdentityModel.Tokens.Jwt.Tests
{
    public class JwtSecurityTokenTests
    {
        [Fact]
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
            Assert.Null(jwt.InnerToken);
            Assert.Null(jwt.RawAuthenticationTag);
            Assert.Null(jwt.RawCiphertext);
            Assert.Null(jwt.RawEncryptedKey);
            Assert.Null(jwt.RawInitializationVector);
            Assert.Null(jwt.EncryptingCredentials);
        }

        [Fact]
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

#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant
        [Theory, MemberData(nameof(EmbeddedTokenConstructorData))]
#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
        public void EmbeddedTokenConstructor1(string testId, JwtSecurityTokenTestVariation outerTokenVariation, JwtSecurityTokenTestVariation innerTokenVariation, string jwt, ExpectedException ee)
        {
            JwtSecurityToken outerJwt = null;
            JwtSecurityToken innerJwt = null;

            // create inner token
            try
            {
                innerJwt = CreateToken(innerTokenVariation);
            }
            catch (Exception ex)
            {
                ee.ProcessException(ex);
            }

            // create outer token
            try
            {
                if (String.IsNullOrEmpty(jwt))
                    outerJwt = new JwtSecurityToken(
                        header: outerTokenVariation.Header,
                        innerToken: innerJwt,
                        rawHeader: outerTokenVariation.RawHeader,
                        rawEncryptedKey: outerTokenVariation.RawEncryptedKey,
                        rawInitializationVector: outerTokenVariation.RawInitializationVector,
                        rawCiphertext: outerTokenVariation.RawCiphertext,
                        rawAuthenticationTag: outerTokenVariation.RawAuthenticationTag);
                else
                    outerJwt = new JwtSecurityToken(jwt);

                outerTokenVariation.ExpectedException.ProcessNoException();
            }
            catch (Exception ex)
            {
                ee.ProcessException(ex);
            }

            try
            {
                // ensure we can get to every outer token property
                if (outerJwt != null && (ee == null || ee.TypeExpected == null))
                {
                    TestUtilities.CallAllPublicInstanceAndStaticPropertyGets(outerJwt, testId);
                }

                if (null != outerTokenVariation.ExpectedJwtSecurityToken)
                {
                    Assert.True(IdentityComparer.AreEqual(outerTokenVariation.ExpectedJwtSecurityToken, outerJwt));
                }
            }
            catch (Exception ex)
            {
                Assert.True(false, string.Format("Testcase: {0}. UnExpected when getting a properties: '{1}'", outerTokenVariation.Name, ex.ToString()));
            }

            try
            {
                // ensure we can get to every inner token property
                if (innerJwt != null && (ee == null || ee.TypeExpected == null))
                {
                    TestUtilities.CallAllPublicInstanceAndStaticPropertyGets(innerJwt, testId);
                }

                if (null != innerTokenVariation.ExpectedJwtSecurityToken)
                {
                    Assert.True(IdentityComparer.AreEqual(innerTokenVariation.ExpectedJwtSecurityToken, innerJwt));
                }
            }
            catch (Exception ex)
            {
                Assert.True(false, string.Format("Testcase: {0}. UnExpected when getting a properties: '{1}'", testId, ex.ToString()));
            }

            try
            {
                if (outerJwt != null && innerJwt != null && (ee == null || ee.TypeExpected == null))
                {
                    // confirm properties of outer token match our expectation
                    Assert.Equal(outerJwt.InnerToken, innerJwt);
                    CheckPayloadProperties(outerJwt, innerJwt);
                    CheckOuterTokenProperties(outerJwt, outerTokenVariation);
                }
            }
            catch (Exception ex)
            {
                Assert.True(false, string.Format("Testcase: {0}. Unexpected inequality between outer and inner token properties: '{1}'", testId, ex.ToString()));
            }

        }

        public static TheoryData<string, JwtSecurityTokenTestVariation, JwtSecurityTokenTestVariation, string, ExpectedException> EmbeddedTokenConstructorData()
        {
            var dataSet = new TheoryData<string, JwtSecurityTokenTestVariation, JwtSecurityTokenTestVariation, string, ExpectedException>();

            dataSet.Add("Embedded token all properties null",
                // outer token
                new JwtSecurityTokenTestVariation
                {
                    RawHeader = null,
                    RawEncryptedKey = null,
                    RawInitializationVector = null,
                    RawCiphertext = null,
                    RawAuthenticationTag = null,
                },
                // inner token
                new JwtSecurityTokenTestVariation
                {
                    Issuer = null,
                    Audience = null,
                    Claims = null,
                    SigningCredentials = null,
                },
                String.Empty,
                ExpectedException.ArgumentNullException()
            );

            string rawHeader, rawEncryptedKey, rawInitializationVector, rawCipherText, rawAuthenticationTag;
            ParseJweParts(EncodedJwts.ValidJweDirect, out rawHeader, out rawEncryptedKey, out rawInitializationVector, out rawCipherText, out rawAuthenticationTag);
            JwtSecurityTokenTestVariation dirOuter = new JwtSecurityTokenTestVariation
            {
                Header = new JwtHeader(Default.SymmetricEncryptingCredentials),
                RawHeader = rawHeader,
                RawEncryptedKey = rawEncryptedKey,
                RawInitializationVector = rawInitializationVector,
                RawCiphertext = rawCipherText,
                RawAuthenticationTag = rawAuthenticationTag
            };
            JwtSecurityTokenTestVariation innerToken = new JwtSecurityTokenTestVariation
            {
                NotBefore = DateTime.MinValue,
                Expires = DateTime.UtcNow,
            };

            dataSet.Add("Dir enc outer token 1- Construct by parts", dirOuter, innerToken, String.Empty, ExpectedException.NoExceptionExpected);
            //dataSet.Add("Dir enc outer token 1- Construct by string", dirOuter, innerToken, EncodedJwts.ValidJweDirect, ExpectedException.NoExceptionExpected);

            ParseJweParts(EncodedJwts.InvalidJweDirect, out rawHeader, out rawEncryptedKey, out rawInitializationVector, out rawCipherText, out rawAuthenticationTag);
            JwtSecurityTokenTestVariation dirOuter2 = new JwtSecurityTokenTestVariation
            {
                Header = new JwtHeader(Default.SymmetricEncryptingCredentials),
                RawHeader = rawHeader,
                RawEncryptedKey = rawEncryptedKey,
                RawInitializationVector = rawInitializationVector,
                RawCiphertext = rawCipherText,
                RawAuthenticationTag = rawAuthenticationTag
            };

            dataSet.Add("Dir enc outer token 3- Construct by parts", dirOuter2, innerToken, String.Empty, ExpectedException.NoExceptionExpected);
            //dataSet.Add("Dir enc outer token 3- Construct by string", dirOuter2, innerToken, EncodedJwts.InvalidJweDirect, ExpectedException.NoExceptionExpected);

            ParseJweParts(EncodedJwts.InvalidJweDirect, out rawHeader, out rawEncryptedKey, out rawInitializationVector, out rawCipherText, out rawAuthenticationTag);
            JwtSecurityTokenTestVariation dirOuter3 = new JwtSecurityTokenTestVariation
            {
                Header = new JwtHeader(Default.SymmetricEncryptingCredentials),
                RawHeader = rawHeader,
                RawEncryptedKey = rawEncryptedKey,
                RawInitializationVector = rawInitializationVector,
                RawCiphertext = rawCipherText,
                RawAuthenticationTag = rawAuthenticationTag
            };

            dataSet.Add("Dir enc outer token 4- Construct by parts", dirOuter2, innerToken, String.Empty, ExpectedException.NoExceptionExpected);
            //dataSet.Add("Dir enc outer token 4- Construct by string", dirOuter2, innerToken, EncodedJwts.InvalidJweDirect, ExpectedException.NoExceptionExpected);

            ParseJweParts(EncodedJwts.InvalidJweDirect2, out rawHeader, out rawEncryptedKey, out rawInitializationVector, out rawCipherText, out rawAuthenticationTag);
            JwtSecurityTokenTestVariation dirOuter4 = new JwtSecurityTokenTestVariation
            {
                Header = new JwtHeader(Default.SymmetricEncryptingCredentials),
                RawHeader = rawHeader,
                RawEncryptedKey = rawEncryptedKey,
                RawInitializationVector = rawInitializationVector,
                RawCiphertext = rawCipherText,
                RawAuthenticationTag = rawAuthenticationTag
            };

            dataSet.Add("Dir enc outer token 5- Construct by parts", dirOuter2, innerToken, String.Empty, ExpectedException.NoExceptionExpected);
            //dataSet.Add("Dir enc outer token 5- Construct by string", dirOuter2, innerToken, EncodedJwts.InvalidJweDirect2, ExpectedException.NoExceptionExpected);

            return dataSet;
        }

        private static void CheckOuterTokenProperties(JwtSecurityToken token, JwtSecurityTokenTestVariation variation)
        {
            Assert.Equal(token.RawHeader, variation.RawHeader);
            Assert.Equal(token.RawEncryptedKey, variation.RawEncryptedKey);
            Assert.Equal(token.RawInitializationVector, variation.RawInitializationVector);
            Assert.Equal(token.RawCiphertext, variation.RawCiphertext);
            Assert.Equal(token.RawAuthenticationTag, variation.RawAuthenticationTag);
        }

        private static void CheckPayloadProperties(JwtSecurityToken token1, JwtSecurityToken token2)
        {
            Assert.Equal(token1.Payload.Acr, token2.Payload.Acr);
            Assert.Equal(token1.Payload.Actort, token2.Payload.Actort);
            Assert.Equal(token1.Payload.Amr, token2.Payload.Amr);
            Assert.Equal(token1.Payload.Aud, token2.Payload.Aud);
            Assert.Equal(token1.Payload.AuthTime, token2.Payload.AuthTime);
            Assert.Equal(token1.Payload.CHash, token2.Payload.CHash);
            Assert.Equal(token1.Payload.Exp, token2.Payload.Exp);
            Assert.Equal(token1.Payload.Iat, token2.Payload.Iat);
            Assert.Equal(token1.Payload.Iss, token2.Payload.Iss);
            Assert.Equal(token1.Payload.Jti, token2.Payload.Jti);
            Assert.Equal(token1.Payload.Keys, token2.Payload.Keys);
            Assert.Equal(token1.Payload.Nbf, token2.Payload.Nbf);
            Assert.Equal(token1.Payload.Nonce, token2.Payload.Nonce);
            Assert.Equal(token1.Payload.Sub, token2.Payload.Sub);
            Assert.Equal(token1.Payload.ValidFrom, token2.Payload.ValidFrom);
            Assert.Equal(token1.Payload.ValidTo, token2.Payload.ValidTo);
        }

        private static void ParseJweParts(string jwe, out string headerPart, out string encryptedKeyPart, out string initializationVectorPart, out string ciphertextPart, out string authenticationTagPart)
        {
            if (String.IsNullOrEmpty(jwe))
                throw new ArgumentNullException(nameof(jwe));

            string[] parts = jwe.Split(new char[] {'.'}, 6);
            if (parts.Length != 5)
                throw new ArgumentException(String.Format("The JWE token must have 5 parts. The JWE {0} has {1} parts.", jwe, parts.Length));

            headerPart = parts[0];
            encryptedKeyPart = parts[1];
            initializationVectorPart = parts[2];
            ciphertextPart = parts[3];
            authenticationTagPart = parts[4];
        }

        private void RunConstructionTest(JwtSecurityTokenTestVariation variation)
        {
            JwtSecurityToken jwt = null;
            try
            {
                jwt = CreateToken(variation);
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

        private JwtSecurityToken CreateToken(JwtSecurityTokenTestVariation variation)
        {
            return new JwtSecurityToken(
                issuer: variation.Issuer,
                audience: variation.Audience,
                claims: variation.Claims,
                signingCredentials: variation.SigningCredentials,
                notBefore: variation.NotBefore,
                expires: variation.Expires);
        }

#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant
        [Theory, MemberData(nameof(ValidEncodedSegmentsData))]
#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
        public void ValidEncodedSegments(string testId, string jwt, ExpectedException ee)
        {
            try
            {
                var jwtToken = new JwtSecurityToken(jwt);
                ee.ProcessNoException();
                TestUtilities.CallAllPublicInstanceAndStaticPropertyGets(jwtToken, testId);
            }
            catch (Exception ex)
            {
                ee.ProcessException(ex);
            }
        }

        public static TheoryData<string, string, ExpectedException> ValidEncodedSegmentsData()
        {
            return JwtTestData.ValidEncodedSegmentsData();
        }

#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant
        [Theory, MemberData(nameof(InvalidEncodedSegmentsData))]
#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
        public void InvalidEncodedSegments(string testId, string jwt, ExpectedException ee)
        {
            try
            {
                var jwtToken = new JwtSecurityToken(jwt);
                ee.ProcessNoException();
                TestUtilities.CallAllPublicInstanceAndStaticPropertyGets(jwtToken, testId);
            }
            catch (Exception ex)
            {
                ee.ProcessException(ex);
            }
        }

        public static TheoryData<string, string, ExpectedException> InvalidEncodedSegmentsData()
        {
            return JwtTestData.InvalidEncodedSegmentsData("");
        }

#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant
        [Theory, MemberData(nameof(InvalidNumberOfSegmentsData))]
#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
        public void InvalidNumberOfSegments(string testId, string jwt, ExpectedException ee)
        {
            try
            {
                new JwtSecurityToken(jwt);

                ee.ProcessNoException();
            }
            catch (Exception ex)
            {
                ee.ProcessException(ex);
            }
        }

        public static TheoryData<string, string, ExpectedException> InvalidNumberOfSegmentsData()
        {
            return JwtTestData.InvalidNumberOfSegmentsData("IDX10709:");
        }

#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant
        [Theory, MemberData(nameof(InvalidRegExSegmentsData))]
#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
        public void InvalidRegExSegments(string testId, string jwt, ExpectedException ee)
        {
            try
            {
                new JwtSecurityToken(jwt);

                ee.ProcessNoException();
            }
            catch (Exception ex)
            {
                ee.ProcessException(ex);
            }
        }

        public static TheoryData<string, string, ExpectedException> InvalidRegExSegmentsData()
        {
            return JwtTestData.InvalidRegExSegmentsData("IDX10709:");
        }
    }
}
