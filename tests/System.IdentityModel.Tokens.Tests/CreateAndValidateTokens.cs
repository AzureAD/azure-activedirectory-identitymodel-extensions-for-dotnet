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
using System.Collections.Generic;
using System.Globalization;
using System.IdentityModel.Tokens;
using System.IO;
using System.Reflection;
using System.Security.Claims;
using System.Xml;
using Xunit;

namespace System.IdentityModel.Test
{
    public class CreateAndValidateTokens
    {
        public class CreateAndValidateParams
        {
            public JwtSecurityToken CompareTo { get; set; }
            public Type ExceptionType { get; set; }
            public SigningCredentials SigningCredentials { get; set; }
            public SecurityToken SigningToken { get; set; }
            public TokenValidationParameters TokenValidationParameters { get; set; }
            public IEnumerable<Claim> Claims { get; set; }
            public string Case { get; set; }
            public string Issuer { get; set; }
        }

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

        [Fact]
        [TestProperty("TestCaseID", "52BE8540-1CA5-4C50-8A38-CE352C88D5D2")]
        [Description("Create Token with X5c's")]
        public void CreateAndValidateTokens_MultipleX5C()
        {
            List<string> errors = new List<string>();
            var handler = new JwtSecurityTokenHandler();
            var payload = new JwtPayload();
            var header = new JwtHeader();

            payload.AddClaims(ClaimSets.MultipleAudiences(IdentityUtilities.DefaultIssuer, IdentityUtilities.DefaultIssuer));
            List<string> x5cs = new List<string> { "x5c1", "x5c2" };
            header.Add(JwtHeaderParameterNames.X5c, x5cs);
            var jwtToken = new JwtSecurityToken(header, payload);
            var jwt = handler.WriteToken(jwtToken);

            var validationParameters =
                new TokenValidationParameters
                {
                    RequireExpirationTime = false,
                    RequireSignedTokens = false,
                    ValidateAudience = false,
                    ValidateIssuer = false,
                    ValidateLifetime = false,
                };

            SecurityToken validatedSecurityToken = null;
            var cp = handler.ValidateToken(jwt, validationParameters, out validatedSecurityToken);

            JwtSecurityToken validatedJwt = validatedSecurityToken as JwtSecurityToken;
            object x5csInHeader = validatedJwt.Header[JwtHeaderParameterNames.X5c];
            if (x5csInHeader == null)
            {
                errors.Add("1: validatedJwt.Header[JwtHeaderParameterNames.X5c]");
            }
            else
            {
                var list = x5csInHeader as IEnumerable<object>;
                if ( list == null )
                {
                    errors.Add("2: var list = x5csInHeader as IEnumerable<object>; is NULL.");
                }

                int num = 0;
                foreach(var str in list)
                {
                    num++;
                    if (!(str is string))
                    {
                        errors.Add("3: str is not string, is:" + str.ToString());
                    }
                }

                if (num != x5cs.Count)
                {
                    errors.Add("4: num != x5cs.Count. num: " + num.ToString() + "x5cs.Count: " + x5cs.Count.ToString());
                }
            }

            // make sure we can still validate with existing logic.
            header = new JwtHeader(KeyingMaterial.DefaultAsymmetricSigningCreds_2048_RsaSha2_Sha2);
            header.Add(JwtHeaderParameterNames.X5c, x5cs);
            jwtToken = new JwtSecurityToken(header, payload);
            jwt = handler.WriteToken(jwtToken);

            validationParameters.IssuerSigningToken = KeyingMaterial.DefaultAsymmetricX509Token_2048;
            validationParameters.RequireSignedTokens = true;
            validatedSecurityToken = null;
            cp = handler.ValidateToken(jwt, validationParameters, out validatedSecurityToken);

            TestUtilities.AssertFailIfErrors(MethodInfo.GetCurrentMethod().Name, errors);
        }

        [TestMethod]
        [TestProperty("TestCaseID", "B14F1FE2-F7A5-450F-8A6D-D0898112570E")]
        [Description("Create Token with multiple audiences")]
        public void CreateAndValidateTokens_MultipleAudiences()
        {
            List<string> errors = new List<string>();

            var handler = new JwtSecurityTokenHandler();
            var payload = new JwtPayload();
            var header = new JwtHeader();

            payload.AddClaims(ClaimSets.MultipleAudiences(IdentityUtilities.DefaultIssuer, IdentityUtilities.DefaultIssuer));
            var jwtToken = new JwtSecurityToken(header, payload);
            var jwt = handler.WriteToken(jwtToken);

            var validationParameters =
                new TokenValidationParameters
                {
                    RequireExpirationTime = false,
                    RequireSignedTokens = false,
                    ValidateAudience = false,
                    ValidateIssuer = false,
                    ValidateLifetime = false,
                };

            SecurityToken validatedJwt = null;
            var cp = handler.ValidateToken(jwt, validationParameters, out validatedJwt);
            var ci = new ClaimsIdentity(ClaimSets.MultipleAudiences(IdentityUtilities.DefaultIssuer, IdentityUtilities.DefaultIssuer), AuthenticationTypes.Federation);
            var cpExpected = new ClaimsPrincipal(ci);
            var compareContext = new CompareContext();
            if (!IdentityComparer.AreEqual<ClaimsPrincipal>(cp, cpExpected, compareContext))
            {
                errors.Add("IdentityComparer.AreEqual<ClaimsPrincipal>(cp, cpExpected, compareContext)");
            }

            var audiences = (validatedJwt as JwtSecurityToken).Audiences;
            var jwtAudiences = jwtToken.Audiences;

            if (!IdentityComparer.AreEqual<IEnumerable<string>>(audiences, jwtAudiences))
            {
                errors.Add("!IdentityComparer.AreEqual<IEnumerable<string>>(audiences, jwtAudiences)");
            }

            if (!IdentityComparer.AreEqual<IEnumerable<string>>(audiences, IdentityUtilities.DefaultAudiences))
            {
                errors.Add("!IdentityComparer.AreEqual<IEnumerable<string>>(audiences, IdentityUtilities.DefaultAudiences)");
            }

            TestUtilities.AssertFailIfErrors(MethodInfo.GetCurrentMethod().Name, errors);
        }

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
        [Description("Ensures that Serializing and Deserializing usin xml or json have same results.")]
        public void CreateAndValidateTokens_RoundTripTokens()
        {
            JwtSecurityTokenHandler handler = new JwtSecurityTokenHandler();
            CreateAndValidateParams createAndValidateParams;
            string issuer = "issuer";
            string originalIssuer = "originalIssuer";

            createAndValidateParams = new CreateAndValidateParams
            {
                Case = "ClaimSets.DuplicateTypes",
                Claims = ClaimSets.DuplicateTypes(issuer, originalIssuer),
                CompareTo = IdentityUtilities.CreateJwtSecurityToken(issuer, originalIssuer, ClaimSets.DuplicateTypes(issuer, originalIssuer), null),
                ExceptionType = null,
                TokenValidationParameters = new TokenValidationParameters
                {
                    RequireSignedTokens = false,
                    ValidateAudience = false,
                    ValidateLifetime = false,
                    ValidateIssuer = false,
                }
            };

            RunRoundTrip(createAndValidateParams, handler);

            createAndValidateParams = new CreateAndValidateParams
            {
                Case = "ClaimSets.Simple_simpleSigned_Asymmetric",
                Claims = ClaimSets.Simple(issuer, originalIssuer),
                CompareTo = IdentityUtilities.CreateJwtSecurityToken(issuer, originalIssuer, ClaimSets.Simple(issuer, originalIssuer), KeyingMaterial.DefaultX509SigningCreds_2048_RsaSha2_Sha2),
                ExceptionType = null,
                SigningCredentials = KeyingMaterial.DefaultX509SigningCreds_2048_RsaSha2_Sha2,
                SigningToken = KeyingMaterial.DefaultX509Token_2048,
                TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateAudience = false,
                    IssuerSigningKey = new X509SecurityKey(KeyingMaterial.DefaultCert_2048),
                    ValidIssuer = issuer,
                }
            };

            RunRoundTrip(createAndValidateParams, handler);

            createAndValidateParams = new CreateAndValidateParams
            {
                Case = "ClaimSets.Simple_simpleSigned_Symmetric",
                Claims = ClaimSets.Simple(issuer, originalIssuer),
                CompareTo = IdentityUtilities.CreateJwtSecurityToken(issuer, originalIssuer, ClaimSets.Simple(issuer, originalIssuer), KeyingMaterial.DefaultSymmetricSigningCreds_256_Sha2),
                ExceptionType = null,
                SigningCredentials = KeyingMaterial.DefaultSymmetricSigningCreds_256_Sha2,
                SigningToken = KeyingMaterial.DefaultSymmetricSecurityToken_256,
                TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateAudience = false,
                    IssuerSigningKey = KeyingMaterial.DefaultSymmetricSecurityKey_256,
                    ValidIssuer = issuer,
                }
            };

            RunRoundTrip(createAndValidateParams, handler);
        }

        private void RunRoundTrip(CreateAndValidateParams jwtParams, JwtSecurityTokenHandler handler)
        {
            SecurityToken validatedToken;

            string jwt = handler.WriteToken(jwtParams.CompareTo);
            ClaimsPrincipal principal = handler.ValidateToken(jwt, jwtParams.TokenValidationParameters, out validatedToken);

            // create from security descriptor
            SecurityTokenDescriptor tokenDescriptor = new SecurityTokenDescriptor();
            tokenDescriptor.SigningCredentials = jwtParams.SigningCredentials;
            tokenDescriptor.Lifetime = new Lifetime(jwtParams.CompareTo.ValidFrom, jwtParams.CompareTo.ValidTo);
            tokenDescriptor.Subject = new ClaimsIdentity(jwtParams.Claims);
            tokenDescriptor.TokenIssuerName = jwtParams.CompareTo.Issuer;
            foreach (string str in jwtParams.CompareTo.Audiences)
            {
                if (!string.IsNullOrWhiteSpace(str))
                {
                    tokenDescriptor.AppliesToAddress = str;
                }
            }


            JwtSecurityToken token = handler.CreateToken(tokenDescriptor) as JwtSecurityToken;
            Assert.IsTrue(IdentityComparer.AreEqual(token, jwtParams.CompareTo), "!IdentityComparer.AreEqual( token, jwtParams.CompareTo )");

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
            JwtSecurityTokenHandler.InboundClaimFilter.Add("aud");
            JwtSecurityTokenHandler.InboundClaimFilter.Add("exp");
            JwtSecurityTokenHandler.InboundClaimFilter.Add("iat");
            JwtSecurityTokenHandler.InboundClaimFilter.Add("iss");
            JwtSecurityTokenHandler.InboundClaimFilter.Add("nbf");

            ClaimsPrincipal claimsPrincipal = tokenHandler.ValidateToken(encodedJwt, IdentityUtilities.DefaultSymmetricTokenValidationParameters, out validatedToken);

            Assert.IsTrue(IdentityComparer.AreEqual<IEnumerable<Claim>>(claimsPrincipal.Claims, ClaimSets.DuplicateTypes(IdentityUtilities.DefaultIssuer, IdentityUtilities.DefaultIssuer), new CompareContext { IgnoreProperties = true, IgnoreSubject = true }));

            JwtSecurityTokenHandler.InboundClaimFilter.Clear();
        }

        [TestMethod]
        [TestProperty("TestCaseID", "FC7354C3-140B-4036-862A-BAFEA948D262")]
        [Description("This test ensures that a Json serialized object, when added as the value of a claim, can be recognized and reconstituted.")]
        public void CreateAndValidateTokens_JsonClaims()
        {
            List<string> errors = new List<string>();

            string issuer = "http://www.GotJWT.com";
            string claimSources = "_claim_sources";
            string claimNames = "_claim_names";

            JwtPayload jwtPayloadClaimSources = new JwtPayload();
            jwtPayloadClaimSources.Add(claimSources, JsonClaims.ClaimSources);
            jwtPayloadClaimSources.Add(claimNames, JsonClaims.ClaimNames);

            JwtSecurityToken jwtClaimSources = 
                new JwtSecurityToken(
                    new JwtHeader(),
                    jwtPayloadClaimSources);

            JwtSecurityTokenHandler jwtHandler = new JwtSecurityTokenHandler();
            string encodedJwt = jwtHandler.WriteToken(jwtClaimSources);
            var validationParameters =
                new TokenValidationParameters
                {
                    IssuerValidator = (s, st, tvp) => { return issuer;},
                    RequireSignedTokens = false,
                    ValidateAudience = false,
                    ValidateLifetime = false,
                };

            SecurityToken validatedJwt = null;
            var claimsPrincipal = jwtHandler.ValidateToken(encodedJwt, validationParameters, out validatedJwt);
            if (!IdentityComparer.AreEqual
                (claimsPrincipal.Identity as ClaimsIdentity,
                 JsonClaims.ClaimsIdentityDistributedClaims(issuer, TokenValidationParameters.DefaultAuthenticationType, JsonClaims.ClaimSources, JsonClaims.ClaimNames)))
            {
                errors.Add("JsonClaims.ClaimSources, JsonClaims.ClaimNames: test failed");
            };

            Claim c = claimsPrincipal.FindFirst(claimSources);
            if (!c.Properties.ContainsKey(JwtSecurityTokenHandler.JsonClaimTypeProperty))
            {
                errors.Add(claimSources + " claim, did not have json property: " + JwtSecurityTokenHandler.JsonClaimTypeProperty);
            }
            else
            {
                if (!string.Equals(c.Properties[JwtSecurityTokenHandler.JsonClaimTypeProperty], typeof(IDictionary<string, object>).ToString(), StringComparison.Ordinal))
                {
                    errors.Add("!string.Equals(c.Properties[JwtSecurityTokenHandler.JsonClaimTypeProperty], typeof(IDictionary<string, object>).ToString(), StringComparison.Ordinal)" +
                        "value is: " + c.Properties[JwtSecurityTokenHandler.JsonClaimTypeProperty]);
                }
            }

            JwtSecurityToken jwtWithEntity =
                new JwtSecurityToken(
                    new JwtHeader(),
                    new JwtPayload(claims: ClaimSets.EntityAsJsonClaim(issuer, issuer)));

            encodedJwt = jwtHandler.WriteToken(jwtWithEntity);
            JwtSecurityToken jwtRead = jwtHandler.ReadToken(encodedJwt) as JwtSecurityToken;

            SecurityToken validatedToken;
            var cp = jwtHandler.ValidateToken(jwtRead.RawData, validationParameters, out validatedToken);
            Claim jsonClaim = cp.FindFirst(typeof(Entity).ToString());
            if (jsonClaim == null)
            {
                errors.Add("Did not find Jsonclaims. Looking for claim of type: '" + typeof(Entity).ToString() + "'");
            };

            string jsString = JsonExtensions.SerializeToJson(Entity.Default);

            if (!string.Equals(jsString, jsonClaim.Value, StringComparison.Ordinal))
            {
                errors.Add(string.Format(CultureInfo.InvariantCulture, "Find Jsonclaims of type: '{0}', but they weren't equal.\nExpecting:\n'{1}'.\nReceived:\n'{2}'", typeof(Entity).ToString(), jsString, jsonClaim.Value));
            }

            TestUtilities.AssertFailIfErrors(MethodInfo.GetCurrentMethod().Name, errors);
        }

        [TestMethod]
        [TestProperty("TestCaseID", "F443747C-5AA1-406D-B0FE-53152CA92DA3")]
        [Description("These test ensures that the SubClaim is used the identity, when ClaimsIdentity.Name is called.")]
        public void CreateAndValidateTokens_SubClaim()
        {
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