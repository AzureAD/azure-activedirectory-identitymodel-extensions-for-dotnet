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

using Microsoft.IdentityModel.Json;
using Microsoft.IdentityModel.Json.Linq;
using Microsoft.IdentityModel.TestUtils;
using Microsoft.IdentityModel.Tokens;
using System;
using System.IdentityModel.Tokens.Jwt;
using Xunit;

#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant

namespace Microsoft.IdentityModel.JsonWebTokens.Tests
{
    public class JsonWebTokenTests
    {
        private string jObject = @"{""intarray"":[1,2,3], ""array"":[1,""2"",3], ""string"":""bob"", ""float"":42.0, ""integer"":42, ""nill"": null, ""bool"" : true}";

        // Test checks to make sure that the JsonWebToken payload is correctly converted to IEnumerable<Claim>.
        [Fact]
        public void GetClaimsFromJObject()
        {
            var context = new CompareContext();
            var jsonWebTokenHandler = new JsonWebTokenHandler();
            var jsonWebTokenString = jsonWebTokenHandler.CreateToken(Default.PayloadString, KeyingMaterial.JsonWebKeyRsa256SigningCredentials);
            var jsonWebToken = new JsonWebToken(jsonWebTokenString);
            var claims = jsonWebToken.Claims;
            IdentityComparer.AreEqual(Default.PayloadClaims, claims, context);
            TestUtilities.AssertFailIfErrors(context);
        }

        // Test checks to make sure that the 'Audiences' claim can be successfully retrieved when multiple audiences are present.
        // It also checks that the rest of the claims match up as well
        [Fact]
        public void GetMultipleAudiences()
        {
            var context = new CompareContext();
            var tokenString = "eyJhbGciOiJSUzI1NiJ9.eyJhdWQiOlsiaHR0cDovL0RlZmF1bHQuQXVkaWVuY2UuY29tIiwiaHR0cDovL0RlZmF1bHQuQXVkaWVuY2UxLmNvbSIsImh0dHA6Ly9EZWZhdWx0LkF1ZGllbmNlMi5jb20iLCJodHRwOi8vRGVmYXVsdC5BdWRpZW5jZTMuY29tIiwiaHR0cDovL0RlZmF1bHQuQXVkaWVuY2U0LmNvbSJdLCJleHAiOjE1Mjg4NTAyNzgsImlhdCI6MTUyODg1MDI3OCwiaXNzIjoiaHR0cDovL0RlZmF1bHQuSXNzdWVyLmNvbSIsIm5vbmNlIjoiRGVmYXVsdC5Ob25jZSIsInN1YiI6InVybjpvYXNpczpuYW1zOnRjOlNBTUw6MS4xOm5hbWVpZC1mb3JtYXQ6WDUwOVN1YmplY3ROYW1lIn0.";
            var jsonWebToken = new JsonWebToken(tokenString);
            var jwtSecurityToken = new JwtSecurityToken(tokenString);
            IdentityComparer.AreEqual(jsonWebToken.Claims, jwtSecurityToken.Claims);
            IdentityComparer.AreEqual(jsonWebToken.Audiences, jwtSecurityToken.Audiences, context);
            TestUtilities.AssertFailIfErrors(context);
        }

        // Test checks to make sure that claim values of various types can be successfully retrieved from the header.
        [Fact]
        public void GetHeaderValues()
        {
            var context = new CompareContext();
            TestUtilities.WriteHeader($"{this}.GetHeaderValues");

            var token = new JsonWebToken(jObject, "{}");

            var intarray = token.GetHeaderValue<int[]>("intarray");
            IdentityComparer.AreEqual(new int[] { 1, 2, 3 }, intarray, context);

            var array = token.GetHeaderValue<object[]>("array");
            IdentityComparer.AreEqual(new object[] { 1L, "2", 3L}, array, context);

            var name = token.GetHeaderValue<string>("string");
            IdentityComparer.AreEqual("bob", name, context);

            var floatingPoint = token.GetHeaderValue<float>("float");
            IdentityComparer.AreEqual(42.0, floatingPoint, context);

            var integer = token.GetHeaderValue<int>("integer");
            IdentityComparer.AreEqual(42, integer, context);

            var nill = token.GetHeaderValue <object> ("nill");
            IdentityComparer.AreEqual(nill, null, context);

            var boolean = token.GetHeaderValue<bool>("bool");
            IdentityComparer.AreEqual(boolean, true, context);

            try // Try to retrieve a value that doesn't exist in the header.
            {
                token.GetHeaderValue<int>("doesnotexist");
            }
            catch (Exception ex)
            {
                ExpectedException.ArgumentException("IDX14303:").ProcessException(ex, context);
            }

            try // Try to retrieve an integer when the value is actually a string.
            {
                token.GetHeaderValue<int>("string");
            } 
            catch (Exception ex)
            {
                ExpectedException.ArgumentException("IDX14305:", typeof(System.FormatException)).ProcessException(ex, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        // Test checks to make sure that claim values of various types can be successfully retrieved from the header.
        [Fact]
        public void TryGetHeaderValues()
        {
            var context = new CompareContext();
            TestUtilities.WriteHeader($"{this}.TryGetHeaderValues");

            var token = new JsonWebToken(jObject, "{}");

            var success = token.TryGetHeaderValue("intarray", out int[] intarray);
            IdentityComparer.AreEqual(new int[] { 1, 2, 3 }, intarray, context);
            IdentityComparer.AreEqual(true, success, context);

            success = token.TryGetHeaderValue("array", out object[] array);
            IdentityComparer.AreEqual(new object[] { 1L, "2", 3L }, array, context);
            IdentityComparer.AreEqual(true, success, context);

            success = token.TryGetHeaderValue("string", out string name);
            IdentityComparer.AreEqual("bob", name, context);
            IdentityComparer.AreEqual(true, success, context);

            success = token.TryGetHeaderValue("float", out float floatingPoint);
            IdentityComparer.AreEqual(42.0, floatingPoint, context);
            IdentityComparer.AreEqual(true, success, context);

            success = token.TryGetHeaderValue("integer", out int integer);
            IdentityComparer.AreEqual(42, integer, context);
            IdentityComparer.AreEqual(true, success, context);

            success = token.TryGetHeaderValue("nill", out object nill);
            IdentityComparer.AreEqual(nill, null, context);
            IdentityComparer.AreEqual(true, success, context);

            success = token.TryGetHeaderValue("bool", out bool boolean);
            IdentityComparer.AreEqual(boolean, true, context);
            IdentityComparer.AreEqual(true, success, context);

            success = token.TryGetHeaderValue("doesnotexist", out int doesNotExist);
            IdentityComparer.AreEqual(0, doesNotExist, context);
            IdentityComparer.AreEqual(false, success, context);

            success = token.TryGetHeaderValue("string", out int cannotConvert);
            IdentityComparer.AreEqual(0, cannotConvert, context);
            IdentityComparer.AreEqual(false, success, context);

            TestUtilities.AssertFailIfErrors(context);
        }

        // Test checks to make sure that claim values of various types can be successfully retrieved from the payload.
        [Fact]
        public void GetPayloadValues()
        {
            var context = new CompareContext();
            TestUtilities.WriteHeader($"{this}.GetPayloadValues");

            var token = new JsonWebToken("{}", jObject);

            var intarray = token.GetPayloadValue<int[]>("intarray");
            IdentityComparer.AreEqual(new int[] { 1, 2, 3 }, intarray, context);

            var array = token.GetPayloadValue<object[]>("array");
            IdentityComparer.AreEqual(new object[] { 1L, "2", 3L }, array, context);

            var name = token.GetPayloadValue<string>("string");
            IdentityComparer.AreEqual("bob", name, context);

            var floatingPoint = token.GetPayloadValue<float>("float");
            IdentityComparer.AreEqual(42.0, floatingPoint, context);

            var integer = token.GetPayloadValue<int>("integer");
            IdentityComparer.AreEqual(42, integer, context);

            var nill = token.GetPayloadValue<object>("nill");
            IdentityComparer.AreEqual(nill, null, context);

            var boolean = token.GetPayloadValue<bool>("bool");
            IdentityComparer.AreEqual(boolean, true, context);

            try // Try to retrieve a value that doesn't exist in the header.
            {
                token.GetPayloadValue<int>("doesnotexist");
            }
            catch (Exception ex)
            {
                ExpectedException.ArgumentException("IDX14304:").ProcessException(ex, context);
            }

            try // Try to retrieve an integer when the value is actually a string.
            {
                token.GetPayloadValue<int>("string");
            }
            catch (Exception ex)
            {
                ExpectedException.ArgumentException("IDX14305:", typeof(System.FormatException)).ProcessException(ex, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        // Test checks to make sure that claim values of various types can be successfully retrieved from the payload.
        [Fact]
        public void TryGetPayloadValues()
        {
            var context = new CompareContext();
            TestUtilities.WriteHeader($"{this}.TryGetPayloadValues");

            var token = new JsonWebToken("{}", jObject);

            var success = token.TryGetPayloadValue("intarray", out int[] intarray);
            IdentityComparer.AreEqual(new int[] { 1, 2, 3 }, intarray, context);
            IdentityComparer.AreEqual(true, success, context);

            success = token.TryGetPayloadValue("array", out object[] array);
            IdentityComparer.AreEqual(new object[] { 1L, "2", 3L }, array, context);
            IdentityComparer.AreEqual(true, success, context);

            success = token.TryGetPayloadValue("string", out string name);
            IdentityComparer.AreEqual("bob", name, context);
            IdentityComparer.AreEqual(true, success, context);

            success = token.TryGetPayloadValue("float", out float floatingPoint);
            IdentityComparer.AreEqual(42.0, floatingPoint, context);
            IdentityComparer.AreEqual(true, success, context);

            success = token.TryGetPayloadValue("integer", out int integer);
            IdentityComparer.AreEqual(42, integer, context);
            IdentityComparer.AreEqual(true, success, context);

            success = token.TryGetPayloadValue("nill", out object nill);
            IdentityComparer.AreEqual(nill, null, context);
            IdentityComparer.AreEqual(true, success, context);

            success = token.TryGetPayloadValue("bool", out bool boolean);
            IdentityComparer.AreEqual(boolean, true, context);
            IdentityComparer.AreEqual(true, success, context);

            success = token.TryGetPayloadValue("doesnotexist", out int doesNotExist);
            IdentityComparer.AreEqual(0, doesNotExist, context);
            IdentityComparer.AreEqual(false, success, context);

            success = token.TryGetPayloadValue("string", out int cannotConvert);
            IdentityComparer.AreEqual(0, cannotConvert, context);
            IdentityComparer.AreEqual(false, success, context);

            TestUtilities.AssertFailIfErrors(context);
        }

        // Time values can be floats, ints, or strings.
        // This test checks to make sure that parsing does not fault in any of the above cases.
        [Theory, MemberData(nameof(ParseTimeValuesTheoryData))]
        public void ParseTimeValues(ParseTimeValuesTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.ParseTimeValues", theoryData);
            var jsonWebTokenHandler = new JsonWebTokenHandler();
            try
            {
                var token = new JsonWebToken(theoryData.Header, theoryData.Payload);
                var validFrom = token.ValidFrom;
                var validTo = token.ValidTo;
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<ParseTimeValuesTheoryData> ParseTimeValuesTheoryData
        {
            get
            {
                return new TheoryData<ParseTimeValuesTheoryData>
                {
                    // Dates as strings
                    new ParseTimeValuesTheoryData
                    {
                        First = true,
                        Payload = Default.PayloadString,
                        Header = new JObject
                        {
                            { JwtHeaderParameterNames.Alg, SecurityAlgorithms.Sha512  },
                            { JwtHeaderParameterNames.Kid, Default.AsymmetricSigningKey.KeyId },
                            { JwtHeaderParameterNames.Typ, JwtConstants.HeaderType }
                        }.ToString(Formatting.None)
                    },
                    // Dates as longs
                    new ParseTimeValuesTheoryData
                    {
                        First = true,
                        Payload = new JObject()
                        {       
                            { JwtRegisteredClaimNames.Email, "Bob@contoso.com" },
                            { JwtRegisteredClaimNames.GivenName, "Bob" },
                            { JwtRegisteredClaimNames.Iss, Default.Issuer },
                            { JwtRegisteredClaimNames.Aud, Default.Audience },
                            { JwtRegisteredClaimNames.Nbf, EpochTime.GetIntDate(Default.NotBefore)},
                            { JwtRegisteredClaimNames.Exp, EpochTime.GetIntDate(Default.Expires) }
                        }.ToString(Formatting.None),
                        Header = new JObject
                        {
                            { JwtHeaderParameterNames.Alg, SecurityAlgorithms.Sha512  },
                            { JwtHeaderParameterNames.Kid, Default.AsymmetricSigningKey.KeyId },
                            { JwtHeaderParameterNames.Typ, JwtConstants.HeaderType }
                        }.ToString(Formatting.None)
                    },
                    // Dates as integers
                    new ParseTimeValuesTheoryData
                    {
                        First = true,
                        Payload = new JObject()
                        {
                            { JwtRegisteredClaimNames.Email, "Bob@contoso.com" },
                            { JwtRegisteredClaimNames.GivenName, "Bob" },
                            { JwtRegisteredClaimNames.Iss, Default.Issuer },
                            { JwtRegisteredClaimNames.Aud, Default.Audience },
                            { JwtRegisteredClaimNames.Nbf, (float) EpochTime.GetIntDate(Default.NotBefore)},
                            { JwtRegisteredClaimNames.Exp, (float) EpochTime.GetIntDate(Default.Expires) }
                        }.ToString(Formatting.None),
                        Header = new JObject
                        {
                            { JwtHeaderParameterNames.Alg, SecurityAlgorithms.Sha512  },
                            { JwtHeaderParameterNames.Kid, Default.AsymmetricSigningKey.KeyId },
                            { JwtHeaderParameterNames.Typ, JwtConstants.HeaderType }
                        }.ToString(Formatting.None)
                    },
                };
            }
        }
    }

    public class ParseTimeValuesTheoryData : TheoryDataBase
    {
        public string Payload { get; set; }

        public string Header { get; set; }
    }
}
