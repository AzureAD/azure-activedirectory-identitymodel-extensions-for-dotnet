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
using Microsoft.IdentityModel.Tests;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace System.IdentityModel.Tokens.Jwt.Tests
{
    /// <summary>
    /// 
    /// </summary>
    public class JwtHeaderTests
    {
        [Fact]
        public void Constructors()
        {
            var header1 = new JwtHeader();
            SigningCredentials signingCredentials = null;
            var header2 = new JwtHeader(signingCredentials);

            var context = new CompareContext
            {
                PropertiesToIgnoreWhenComparing = new Dictionary<Type, List<string>>
                {
                    { typeof(JwtHeader), new List<string> { "Item" } },
                }
            };

            IdentityComparer.AreEqual(header1, header2, context);
            TestUtilities.AssertFailIfErrors("JwtHeaderTests.Constructors", context.Diffs);
        }

        [Fact]
        public void Defaults()
        {
            JwtHeader jwtHeader = new JwtHeader();
            Assert.True(jwtHeader.Typ == JwtConstants.HeaderType, "jwtHeader.ContainsValue( JwtConstants.HeaderType )");
            Assert.True(jwtHeader.Alg == SecurityAlgorithms.None, "jwtHeader.SignatureAlgorithm == null");
            Assert.True(jwtHeader.SigningCredentials == null, "jwtHeader.SigningCredentials != null");
            Assert.True(jwtHeader.Kid == null, "jwtHeader.Kid == null");
            Assert.True(jwtHeader.X5t == null, "jwtHeader.X5t == null");
            Assert.True(jwtHeader.Comparer.GetType() == StringComparer.Ordinal.GetType(), "jwtHeader.Comparer.GetType() != StringComparer.Ordinal.GetType()");
        }

        [Fact]
        public void GetSets()
        {
            var jwtHeader = new JwtHeader();
            Type type = typeof(JwtHeader);
            PropertyInfo[] properties = type.GetProperties();
            if (properties.Length != 14)
                Assert.True(false, "Number of properties has changed from 14 to: " + properties.Length + ", adjust tests");

            GetSetContext context =
                new GetSetContext
                {
                    PropertyNamesAndSetGetValue = new List<KeyValuePair<string, List<object>>>
                    {
                        new KeyValuePair<string, List<object>>("Alg", new List<object>{SecurityAlgorithms.None, Guid.NewGuid().ToString()}),
                        new KeyValuePair<string, List<object>>("Cty", new List<object>{(string)null, Guid.NewGuid().ToString()}),
                        new KeyValuePair<string, List<object>>("Enc", new List<object>{(string)null, Guid.NewGuid().ToString()}),
                        new KeyValuePair<string, List<object>>("EncryptingCredentials", new List<object>{(EncryptingCredentials)null, Default.SymmetricEncryptingCredentials}),
                        new KeyValuePair<string, List<object>>("IV", new List<object>{(string)null, Guid.NewGuid().ToString()}),
                        new KeyValuePair<string, List<object>>("Kid", new List<object>{(string)null, Guid.NewGuid().ToString()}),
                        new KeyValuePair<string, List<object>>("SigningCredentials", new List<object>{(SigningCredentials)null, Default.AsymmetricSigningCredentials}),
                        new KeyValuePair<string, List<object>>("Typ", new List<object>{JwtConstants.HeaderType, Guid.NewGuid().ToString()}),
                        new KeyValuePair<string, List<object>>("X5t", new List<object>{(string)null, Guid.NewGuid().ToString()}),
                    },
                    Object = jwtHeader,
                };
            TestUtilities.GetSet(context);
            TestUtilities.AssertFailIfErrors("JwtHeader_GetSets", context.Errors);
        }

        [Fact]
        public void Publics()
        {
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
