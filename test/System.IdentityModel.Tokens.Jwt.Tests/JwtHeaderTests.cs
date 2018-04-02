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

#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant

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

        // Test checks to make sure that GetStandardClaim() returns null (not "null") if the value associated with the claimType parameter is null.
        [Fact]
        public void GetStandardClaimNull()
        {
            var jwtHeader = new JwtHeader();
            jwtHeader[JwtHeaderParameterNames.Kid] = null;
            var kid = jwtHeader.Kid;
            Assert.True(kid == null);
        }
    }

    public class JwtHeaderTheoryData : TheoryDataBase
    {
        public IDictionary<string, string > OutboundAlgorithmMap { get; set; }

        public SigningCredentials SigningCredentials { get; set; }
   }
}

#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
