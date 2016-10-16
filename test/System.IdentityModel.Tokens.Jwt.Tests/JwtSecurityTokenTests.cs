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
