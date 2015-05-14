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

using System.IdentityModel.Tokens;
using Xunit;

namespace System.IdentityModel.Test
{
    /// <summary>
    /// 
    /// </summary>
    public class JwtHeaderTests
    {
        [Fact(DisplayName = "JwtHeaderTests: Constructors")]
        public void Constructors()
        {
        }

        [Fact(DisplayName = "JwtHeaderTests: Defaults")]
        public void Defaults()
        {
            JwtHeader jwtHeader = new JwtHeader();
            Assert.False(jwtHeader.ContainsValue(JwtConstants.HeaderType), "jwtHeader.ContainsValue( JwtConstants.HeaderType )");
            Assert.False(jwtHeader.ContainsValue(JwtHeaderParameterNames.Typ), "jwtHeader.ContainsValue( JwtConstans.ReservedHeaderParameters.Type )");
            Assert.False(jwtHeader.ContainsKey(JwtHeaderParameterNames.Alg), "!jwtHeader.ContainsKey( JwtHeaderParameterNames.Algorithm )");
            Assert.True(jwtHeader.Alg == null, "jwtHeader.SignatureAlgorithm == null");
            Assert.True(jwtHeader.SigningCredentials == null, "jwtHeader.SigningCredentials != null");
            Assert.True(jwtHeader.Kid == null, "jwtHeader.Kid == null");
            Assert.True(jwtHeader.Comparer.GetType() == StringComparer.Ordinal.GetType(), "jwtHeader.Comparer.GetType() != StringComparer.Ordinal.GetType()");
        }

        [Fact(DisplayName = "JwtHeaderTests: GetSets")]
        public void GetSets()
        {
        }

        [Fact(DisplayName = "JwtHeaderTests: Publics")]
        public void Publics()
        {
        }
    }
}