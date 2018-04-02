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
using Microsoft.IdentityModel.Tests;
using Microsoft.IdentityModel.Tokens;
using Xunit;
using Newtonsoft.Json.Linq;
using System.Text;

#if System
namespace System.IdentityModel.Tokens.Jwt.Tests
#else
using System;
namespace Microsoft.IdentityModel.Tokens.Jwt.Tests
#endif
{
    /// <summary>
    /// 
    /// </summary>
    public class JwtHeaderTests
    {
        [Fact]
        public void Constructors_Default()
        {
            var jwtHeader = new JwtHeader();

            Assert.True(jwtHeader.Typ == null, "jwtHeader.Typ != null");
            Assert.True(jwtHeader.Alg == null, "jwtHeader.Alg != null");
            Assert.True(jwtHeader.SigningCredentials == null, "jwtHeader.SigningCredentials != null");
            Assert.True(jwtHeader.Kid == null, "jwtHeader.Kid == null");
            Assert.True(jwtHeader.Comparer.GetType() == StringComparer.Ordinal.GetType(), "jwtHeader.Comparer.GetType() != StringComparer.Ordinal.GetType()");
        }

        [Fact]
        public void Constructors_Null_SigningCredentials()
        {
            JwtHeader jwtHeader = new JwtHeader((SigningCredentials)null);
            Assert.True(jwtHeader.Typ == JwtConstants.HeaderType, "jwtHeader.ContainsValue( JwtConstants.HeaderType )");
            Assert.True(jwtHeader.Alg == SecurityAlgorithms.None, "jwtHeader.SignatureAlgorithm == null");
            Assert.True(jwtHeader.SigningCredentials == null, "jwtHeader.SigningCredentials != null");
            Assert.True(jwtHeader.Kid == null, "jwtHeader.Kid == null");
            Assert.True(jwtHeader.Comparer.GetType() == StringComparer.Ordinal.GetType(), "jwtHeader.Comparer.GetType() != StringComparer.Ordinal.GetType()");
        }

        /// <summary>
        /// Ensures that serailization roundtrip is maintained for encoding.
        /// </summary>
        [Fact]
        public void RoundTripSerialization()
        {
            var propertyNames = new List<string>
            {
                {"Alg"},
                {"Cty"},
                {"Enc"},
                {"IV"},
                {"Kid"},
                {"Typ"},
                {"X5t"}
            };

            var dictionaryKeys = new List<string>
            {
                {JwtHeaderParameterNames.Alg},
                {JwtHeaderParameterNames.Cty},
                {JwtHeaderParameterNames.Enc},
                {JwtHeaderParameterNames.IV},
                {JwtHeaderParameterNames.Kid},
                {JwtHeaderParameterNames.Typ},
                {JwtHeaderParameterNames.X5t}
            };

            for (int i = 0; i < propertyNames.Count; i++)
                RunVariationSerialization(i, propertyNames, dictionaryKeys);
        }

        private void RunVariationSerialization(int start, List<string> propertyNames, List<string> dictionaryKeys)
        {
            var jwtHeaderPropertyValues = new Dictionary<string, string>();
            for (int i = 0; i < dictionaryKeys.Count; i++)
            {
                var index = (i + start) % dictionaryKeys.Count;
                jwtHeaderPropertyValues.Add(dictionaryKeys[(i + start) % dictionaryKeys.Count], Guid.NewGuid().ToString());
            }

            var jwtHeaderExpectedValues = new Dictionary<string, string>();
            for (int i = 0; i < propertyNames.Count; i++)
                jwtHeaderExpectedValues.Add(propertyNames[(i + start) % propertyNames.Count], jwtHeaderPropertyValues[dictionaryKeys[(i + start) % propertyNames.Count]]);

            var stringBuilder = new StringBuilder("{");
            var current = 1;
            foreach (var key in jwtHeaderPropertyValues.Keys)
            {
                stringBuilder.Append($"\"{key}\":\"{jwtHeaderPropertyValues[key]}\"");
                if (current++ < jwtHeaderPropertyValues.Count)
                    stringBuilder.Append(",");
            }
            stringBuilder.Append("}");

            // check that header properties are as expected
            var jwtHeader = JwtHeader.Deserialize(stringBuilder.ToString());
            foreach (var propertyName in jwtHeaderExpectedValues.Keys)
                Assert.Equal(TestUtilities.GetProperty(jwtHeader, propertyName), jwtHeaderExpectedValues[propertyName]);

            // check that dictionary values are as expected
            foreach (var headerKey in jwtHeaderPropertyValues.Keys)
                Assert.Equal(jwtHeader[headerKey], jwtHeaderPropertyValues[headerKey]);

            // check that headers are in the expected order, compare ordered lists
            var jwtHeaderExpectedOrderedValues = new List<string>();
            foreach (var propertyValue in jwtHeaderPropertyValues.Values)
                jwtHeaderExpectedOrderedValues.Add(propertyValue);

            var jwtHeaderActualOrderedValues = new List<string>();
            foreach (var propertyValue in jwtHeader.Values)
                jwtHeaderActualOrderedValues.Add(propertyValue as string);

            for (int index = 0; index < jwtHeaderActualOrderedValues.Count; index++)
                Assert.Equal(jwtHeaderExpectedOrderedValues[index], jwtHeaderActualOrderedValues[index]);

            // compare serialization
            var headerAsJson = jwtHeader.SerializeToJson();
            var expectedJson = stringBuilder.ToString();
            Assert.Equal(expectedJson, headerAsJson);

            // roundtrip
            var headerAsBase64UrlEncoded = jwtHeader.Base64UrlEncode();
            var hydratedHeader = JwtHeader.Base64UrlDeserialize(headerAsBase64UrlEncoded);
            var hydratedHeaderAsJson = hydratedHeader.SerializeToJson();
            Assert.Equal(headerAsJson, hydratedHeaderAsJson);

            var headerFromHydrated = JObject.Parse(hydratedHeaderAsJson);
            var headerEncoded = JObject.Parse(Base64UrlEncoder.Decode(headerAsBase64UrlEncoded));
            Assert.Equal(headerFromHydrated, headerEncoded);
        }

        [Fact]
        public void Kid()
        {
            var jsonWebKey = new JsonWebKey(DataSets.JsonWebKeyString1);
            var credentials = new SigningCredentials(jsonWebKey, SecurityAlgorithms.RsaSha256Signature);
            var token = new JwtSecurityToken(claims: Default.Claims, signingCredentials: credentials);
            Assert.Equal(jsonWebKey.Kid, token.Header.Kid);
        }
    }
}
