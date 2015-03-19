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

using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.IdentityModel.Tokens;
using Microsoft.IdentityModel.Test;
using System.Security.Claims;

namespace System.IdentityModel.Test
{
    /// <summary>
    /// 
    /// </summary>
    [TestClass]
    public class JwtHeaderTests
    {
        public TestContext TestContext { get; set; }

        [ClassInitialize]
        public static void ClassSetup(TestContext testContext)
        {
        }

        [ClassCleanup]
        public static void ClassCleanup()
        {
        }

        [TestInitialize]
        public void Initialize()
        {
        }

        [TestMethod]
        [TestProperty("TestCaseID", "cce4fb01-5835-4b01-af0c-e922f2ae3785")]
        [Description("Tests: Constructors")]
        public void JwtHeader_Constructors()
        {
        }

        [TestMethod]
        [TestProperty("TestCaseID", "E01771B7-2D9E-435E-A933-09FAB429881E")]
        [Description("Ensures that JwtHeader defaults are as expected")]
        public void JwtHeader_Defaults()
        {
            JwtHeader jwtHeader = new JwtHeader();
            Assert.IsFalse(jwtHeader.ContainsValue(JwtConstants.HeaderType), "jwtHeader.ContainsValue( JwtConstants.HeaderType )");
            Assert.IsFalse(jwtHeader.ContainsValue(JwtHeaderParameterNames.Typ), "jwtHeader.ContainsValue( JwtConstans.ReservedHeaderParameters.Type )");
            Assert.IsFalse(jwtHeader.ContainsKey(JwtHeaderParameterNames.Alg), "!jwtHeader.ContainsKey( JwtHeaderParameterNames.Algorithm )");
            Assert.IsNull(jwtHeader.Alg, "jwtHeader.SignatureAlgorithm == null");
            Assert.IsNull(jwtHeader.SigningCredentials, "jwtHeader.SigningCredentials != null");
            Assert.IsNotNull(jwtHeader.SigningKeyIdentifier, "jwtHeader.SigningKeyIdentifier == null");
            Assert.AreEqual(jwtHeader.SigningKeyIdentifier.Count, 0, "jwtHeader.SigningKeyIdentifier.Count !== 0");
            Assert.AreEqual(jwtHeader.Comparer.GetType(), StringComparer.Ordinal.GetType(), "jwtHeader.Comparer.GetType() != StringComparer.Ordinal.GetType()");
        }

        [TestMethod]
        [TestProperty("TestCaseID", "714f9f6a-40af-497f-8452-4f202e8d4af2")]
        [Description("Tests: GetSets")]
        public void JwtHeader_GetSets()
        {
        }

        [TestMethod]
        [TestProperty("TestCaseID", "34478ec3-3dac-4ede-bea0-15373df33257")]
        [Description("Tests: Publics")]
        public void JwtHeader_Publics()
        {
        }

        [TestMethod]
        [TestProperty("TestCaseID", "6B9F5AAA-6362-41A6-99A1-4AA55787ADEE")]
        [Description("Tests: SigningKeyIdentifier")]
        public void JwtHeader_SigningKeyIdentifier()
        {
            var cert = KeyingMaterial.DefaultAsymmetricCert_2048;
            var header = new JwtHeader(new X509SigningCredentials(cert));
            var payload = new JwtPayload( new Claim[]{new Claim("iss", "issuer")});
            var jwt = new JwtSecurityToken(header, payload, header.Base64UrlEncode(), payload.Base64UrlEncode(), "");
            var handler = new JwtSecurityTokenHandler();
            var signedJwt = handler.WriteToken(jwt);
            SecurityToken token = null;
            var validationParameters =
                new TokenValidationParameters
                {
                    IssuerSigningToken = new X509SecurityToken(cert),
                    ValidateAudience = false,
                    ValidateIssuer = false,
                    ValidateLifetime = false,
                };

            handler.ValidateToken(signedJwt, validationParameters, out token);

            validationParameters =
                new TokenValidationParameters
                {
                    IssuerSigningKey = new X509SecurityKey(cert),
                    ValidateAudience = false,
                    ValidateIssuer = false,
                    ValidateLifetime = false,
                };

            handler.ValidateToken(signedJwt, validationParameters, out token);
        }
    }
}