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

using Microsoft.IdentityModel.Test;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Collections.Generic;
using System.Globalization;
using System.IdentityModel.Protocols.WSTrust;
using System.IdentityModel.Selectors;
using System.IdentityModel.Tokens;
using System.IO;
using System.Reflection;
using System.Security.Claims;
using System.Web.Script.Serialization;
using System.Xml;

namespace System.IdentityModel.Test
{
    [TestClass]
    public class CreateAndValidateTokens
    {
        private static string _roleClaimTypeForDelegate = "RoleClaimTypeForDelegate";
        private static string _nameClaimTypeForDelegate = "NameClaimTypeForDelegate";

        [ClassInitialize]
        public static void ClassSetup(TestContext testContext)
        {
        }

        [TestInitialize]
        public void Initialize()
        {
        }

        /// <summary>
        /// The test context that is set by Visual Studio and TAEF - need to keep this exact signature
        /// </summary>
        public TestContext TestContext { get; set; }

        [TestMethod]
        [TestProperty("TestCaseID", "0FA94A41-B904-46C9-B9F1-BF0AEC23045A")]
        [Description("Create EMPTY JwtToken")]
        public void CreateAndValidateTokens_EmptyToken()
        {
            JwtSecurityTokenHandler handler = new JwtSecurityTokenHandler();
            string jwt = handler.WriteToken(new JwtSecurityToken("", ""));
            JwtSecurityToken token = new JwtSecurityToken(jwt);
            Assert.IsTrue(IdentityComparer.AreEqual<JwtSecurityToken>(token, new JwtSecurityToken("", "")));
        }

        [TestMethod]
        [TestProperty("TestCaseID", "8058D994-9600-455D-8B6C-753DE2E26529")]
        [Description("Serialize / Deserialize in different ways.")]
        public void CreateAndValidateTokens_RoundTripTokens()
        {
            SecurityToken validatedToken;
            JwtSecurityTokenHandler handler = new JwtSecurityTokenHandler();
            //handler.CertificateValidator = X509CertificateValidator.None;

            foreach (CreateAndValidateParams jwtParams in JwtTestTokens.All)
            {
                Console.WriteLine("Validating streaming from JwtSecurityToken and TokenValidationParameters is same for Case: '" + jwtParams.Case);

                string jwt = handler.WriteToken(jwtParams.CompareTo);
                ClaimsPrincipal principal = handler.ValidateToken(jwt, jwtParams.TokenValidationParameters, out validatedToken);

                // create from security descriptor
                SecurityTokenDescriptor tokenDescriptor = new SecurityTokenDescriptor();
                tokenDescriptor.SigningCredentials = jwtParams.SigningCredentials;
                tokenDescriptor.Lifetime = new Lifetime(jwtParams.CompareTo.ValidFrom, jwtParams.CompareTo.ValidTo);
                tokenDescriptor.Subject = new ClaimsIdentity(jwtParams.Claims);
                tokenDescriptor.TokenIssuerName = jwtParams.CompareTo.Issuer;
                tokenDescriptor.AppliesToAddress = jwtParams.CompareTo.Audience;

                JwtSecurityToken token = handler.CreateToken(tokenDescriptor) as JwtSecurityToken;
                Assert.IsFalse(!IdentityComparer.AreEqual(token, jwtParams.CompareTo), "!IdentityComparer.AreEqual( token, jwtParams.CompareTo )");

                // write as xml
                MemoryStream ms = new MemoryStream();
                XmlDictionaryWriter writer = XmlDictionaryWriter.CreateDictionaryWriter(XmlTextWriter.Create(ms));
                handler.WriteToken(writer, jwtParams.CompareTo);
                writer.Flush();
                ms.Flush();
                ms.Seek(0, SeekOrigin.Begin);
                XmlDictionaryReader reader = XmlDictionaryReader.CreateTextReader(ms, XmlDictionaryReaderQuotas.Max);
                reader.Read();
                token = handler.ReadToken(reader) as JwtSecurityToken;
                ms.Close();
                IdentityComparer.AreEqual(token, jwtParams.CompareTo);
            }
        }

        [TestMethod]
        [TestProperty("TestCaseID", "DD27BA83-2621-4DF9-A863-C436A9F73BB9")]
        [Description("These Jwts are created with duplicate claims. This test ensure that multiple claims are roundtripped")]
        public void CreateAndValidateTokens_DuplicateClaims()
        {
            SecurityToken validatedToken;
            string encodedJwt = IdentityUtilities.CreateJwtToken(
                new SecurityTokenDescriptor
                { 
                    AppliesToAddress = IdentityUtilities.DefaultAudience,
                    SigningCredentials = IdentityUtilities.DefaultSymmetricSigningCredentials,
                    Subject = new ClaimsIdentity(ClaimSets.DuplicateTypes(IdentityUtilities.DefaultIssuer, IdentityUtilities.DefaultIssuer)),
                    TokenIssuerName = IdentityUtilities.DefaultIssuer,
                });

            JwtSecurityTokenHandler tokenHandler = new JwtSecurityTokenHandler();
            ClaimsPrincipal claimsPrincipal = tokenHandler.ValidateToken(encodedJwt, IdentityUtilities.DefaultSymmetricTokenValidationParameters, out validatedToken);

            Assert.IsTrue(IdentityComparer.AreEqual<IEnumerable<Claim>>(claimsPrincipal.Claims, ClaimSets.DuplicateTypes(IdentityUtilities.DefaultIssuer, IdentityUtilities.DefaultIssuer), new CompareContext { IgnoreProperties = true, IgnoreSubject = true }));
        }

        [TestMethod]
        [TestProperty("TestCaseID", "FC7354C3-140B-4036-862A-BAFEA948D262")]
        [Description("This test ensures that a Json serialized object, when added as the value of a claim, can be recognized and reconstituted.")]
        public void CreateAndValidateTokens_JsonClaims()
        {
            string issuer = "http://www.GotJWT.com";
            string audience = "http://www.contoso.com";

            JwtSecurityToken jwt = new JwtSecurityToken(issuer: issuer, audience: audience, claims: ClaimSets.JsonClaims(issuer, issuer), lifetime: new Lifetime(DateTime.UtcNow, DateTime.UtcNow + TimeSpan.FromHours(1)));
            JwtSecurityTokenHandler jwtHandler = new JwtSecurityTokenHandler();
            string encodedJwt = jwtHandler.WriteToken(jwt);
            JwtSecurityToken jwtRead = jwtHandler.ReadToken(encodedJwt) as JwtSecurityToken;
            TokenValidationParameters validationParameters = new TokenValidationParameters()
            {
                RequireSignedTokens = false,
                ValidateAudience = false,
                ValidIssuer = issuer,
            };

            SecurityToken validatedToken;
            var cp = jwtHandler.ValidateToken(jwtRead.RawData, validationParameters, out validatedToken);
            Claim jsonClaim = cp.FindFirst(typeof(Entity).ToString());
            Assert.IsFalse(jsonClaim == null, "Did not find Jsonclaims. Looking for claim of type: '" + typeof(Entity).ToString() + "'");

            JavaScriptSerializer js = new JavaScriptSerializer();
            string jsString = js.Serialize(Entity.Default);
            Assert.IsFalse(jsString != jsonClaim.Value, string.Format(CultureInfo.InvariantCulture, "Find Jsonclaims of type: '{0}', but they weren't equal.\nExpecting '{1}'.\nReceived '{2}'", typeof(Entity).ToString(), jsString, jsonClaim.Value));
        }

        [TestMethod]
        [TestProperty("TestCaseID", "F443747C-5AA1-406D-B0FE-53152CA92DA3")]
        [Description("These test ensures that the SubClaim is used the identity, when ClaimsIdentity.Name is called.")]
        public void CreateAndValidateTokens_SubClaim()
        {
            string issuer = "http://www.GotJWT.com";
            string audience = "http://www.contoso.com";
            SecurityToken validatedToken;

            JwtSecurityToken jwt = new JwtSecurityToken(issuer: issuer, audience: audience, claims: ClaimSets.JsonClaims(issuer, issuer), lifetime: new Lifetime(DateTime.UtcNow, DateTime.UtcNow + TimeSpan.FromHours(1)));
            JwtSecurityTokenHandler jwtHandler = new JwtSecurityTokenHandler();
            string encodedJwt = jwtHandler.WriteToken(jwt);
            JwtSecurityToken jwtRead = jwtHandler.ReadToken(encodedJwt) as JwtSecurityToken;
            TokenValidationParameters validationParameters = new TokenValidationParameters()
            {
                RequireSignedTokens = false,
                ValidateAudience = false,
                ValidIssuer = issuer,
            };

            var cp = jwtHandler.ValidateToken(jwtRead.RawData, validationParameters, out validatedToken);
            Claim jsonClaim = cp.FindFirst(typeof(Entity).ToString());
            Assert.IsFalse(jsonClaim == null, string.Format(CultureInfo.InvariantCulture, "Did not find Jsonclaims. Looking for claim of type: '{0}'", typeof(Entity).ToString()));

            JavaScriptSerializer js = new JavaScriptSerializer();
            string jsString = js.Serialize(Entity.Default);
            Assert.IsFalse(jsString != jsonClaim.Value, string.Format(CultureInfo.InvariantCulture, "Find Jsonclaims of type: '{0}', but they weren't equal.\nExpecting '{1}'.\nReceived '{2}'", typeof(Entity).ToString(), jsString, jsonClaim.Value));
        }

        private static string NameClaimTypeDelegate(SecurityToken jwt, string issuer)
        {
            return _nameClaimTypeForDelegate;
        }

        private static string RoleClaimTypeDelegate(SecurityToken jwt, string issuer)
        {
            return _roleClaimTypeForDelegate;
        }

        [TestMethod]
        [TestProperty("TestCaseID", "A0DF768E-5073-49E7-90C9-ED97BDCF4B9F")]
        [Description("Tests Name and Role claim delegates")]
        public void CreateAndValidateTokens_NameAndRoleClaimDelegates()
        {
            string defaultName = "defaultName";
            string defaultRole = "defaultRole";
            string delegateName = "delegateName";
            string delegateRole = "delegateRole";
            string validationParameterName = "validationParameterName";
            string validationParameterRole = "validationParameterRole";
            string validationParametersNameClaimType = "validationParametersNameClaimType";
            string validationParametersRoleClaimType = "validationParametersRoleClaimType";

            JwtSecurityTokenHandler handler = new JwtSecurityTokenHandler();
            TokenValidationParameters validationParameters = new TokenValidationParameters
            {
                IssuerSigningToken = KeyingMaterial.DefaultX509Token_2048,
                NameClaimType = validationParametersNameClaimType,
                RoleClaimType = validationParametersRoleClaimType,
                ValidateAudience = false,
                ValidateIssuer = false,
            };

            ClaimsIdentity subject =
                new ClaimsIdentity(
                    new List<Claim> 
                    {   new Claim(_nameClaimTypeForDelegate, delegateName), 
                        new Claim(validationParametersNameClaimType, validationParameterName), 
                        new Claim(ClaimsIdentity.DefaultNameClaimType, defaultName), 
                        new Claim(_roleClaimTypeForDelegate, delegateRole),
                        new Claim(validationParametersRoleClaimType, validationParameterRole), 
                        new Claim(ClaimsIdentity.DefaultRoleClaimType, defaultRole), 
                    });

            JwtSecurityToken jwt = handler.CreateToken(issuer: "https://gotjwt.com", signingCredentials: KeyingMaterial.DefaultX509SigningCreds_2048_RsaSha2_Sha2, subject: subject) as JwtSecurityToken;

            // Delegates should override any other settings
            validationParameters.NameClaimTypeRetriever = NameClaimTypeDelegate;
            validationParameters.RoleClaimTypeRetriever = RoleClaimTypeDelegate;

            SecurityToken validatedToken;
            ClaimsPrincipal principal = handler.ValidateToken(jwt.RawData, validationParameters, out validatedToken);
            CheckNamesAndRole(new string[] { delegateName, defaultName, validationParameterName }, new string[] { delegateRole, defaultRole, validationParameterRole }, principal, _nameClaimTypeForDelegate, _roleClaimTypeForDelegate);

            // Set delegates to null will use TVP values
            validationParameters.NameClaimTypeRetriever = null;
            validationParameters.RoleClaimTypeRetriever = null;
            principal = handler.ValidateToken(jwt.RawData, validationParameters, out validatedToken);
            CheckNamesAndRole(new string[] { validationParameterName, defaultName, delegateName }, new string[] { validationParameterRole, defaultRole, delegateRole }, principal, validationParametersNameClaimType, validationParametersRoleClaimType);

            // check for defaults
            validationParameters = new TokenValidationParameters
            {
                IssuerSigningToken = KeyingMaterial.DefaultX509Token_2048,
                ValidateAudience = false,
                ValidateIssuer = false,
            };

            principal = handler.ValidateToken(jwt.RawData, validationParameters, out validatedToken);
            CheckNamesAndRole(new string[] { defaultName, validationParameterName, delegateName }, new string[] { defaultRole, validationParameterRole, delegateRole }, principal);
        }

        /// <summary>
        /// First string is expected, others are not.
        /// </summary>
        /// <param name="names"></param>
        /// <param name="roles"></param>
        private void CheckNamesAndRole(string[] names, string[] roles, ClaimsPrincipal principal, string expectedNameClaimType = ClaimsIdentity.DefaultNameClaimType, string expectedRoleClaimType = ClaimsIdentity.DefaultRoleClaimType)
        {
            ClaimsIdentity identity = principal.Identity as ClaimsIdentity;
            Assert.AreEqual(identity.NameClaimType, expectedNameClaimType);
            Assert.AreEqual(identity.RoleClaimType, expectedRoleClaimType);
            Assert.IsTrue(principal.IsInRole(roles[0]));
            for (int i = 1; i < roles.Length; i++)
            {
                Assert.IsFalse(principal.IsInRole(roles[i]));
            }

            Assert.AreEqual(identity.Name, names[0]);
            for (int i = 1; i < names.Length; i++)
            {
                Assert.AreNotEqual(identity.Name, names[i]);
            }
        }
    }
}