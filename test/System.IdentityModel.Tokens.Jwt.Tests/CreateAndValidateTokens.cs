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

using System;
using System.Collections.Generic;
using System.Globalization;
using System.IdentityModel.Tokens.Tests;
using System.Security.Claims;
using Xunit;

namespace System.IdentityModel.Tokens.Jwt.Tests
{
    public class CreateAndValidateTokens
    {
        public class CreateAndValidateParams
        {
            public string Case { get; set; }

            public JwtSecurityToken CompareTo { get; set; }

            public Type ExceptionType { get; set; }

            public SecurityTokenDescriptor SecurityTokenDescriptor { get; set; }

            public TokenValidationParameters TokenValidationParameters { get; set; }
        }

        private static string _roleClaimTypeForDelegate = "RoleClaimTypeForDelegate";
        private static string _nameClaimTypeForDelegate = "NameClaimTypeForDelegate";

        [Fact(DisplayName = "CreateAndValidateTokens: CreateAndValidateTokens_MultipleX5C")]
        public void MultipleX5C()
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
                if (list == null)
                {
                    errors.Add("2: var list = x5csInHeader as IEnumerable<object>; is NULL.");
                }

                int num = 0;
                foreach (var str in list)
                {
                    var value = str as Newtonsoft.Json.Linq.JValue;
                    if (value != null)
                    {
                        string aud = value.Value as string;
                        if (aud != null)
                        {

                        }
                    }
                    else if (!(str is string))
                    {
                        errors.Add("3: str is not string, is: " + str.GetType());
                        errors.Add("token : " + validatedJwt.ToString());
                    }
                    num++;
                }

                if (num != x5cs.Count)
                {
                    errors.Add("4: num != x5cs.Count. num: " + num.ToString() + "x5cs.Count: " + x5cs.Count.ToString());
                }
            }

            X509SecurityKey signingKey = KeyingMaterial.X509SecurityKeySelfSigned2048_SHA256;
            X509SecurityKey validateKey = KeyingMaterial.X509SecurityKeySelfSigned2048_SHA256_Public;

            // make sure we can still validate with existing logic.
            SigningCredentials signingCredentials = new SigningCredentials(signingKey, SecurityAlgorithms.RsaSha256Signature);
            header = new JwtHeader(signingCredentials);
            header.Add(JwtHeaderParameterNames.X5c, x5cs);
            jwtToken = new JwtSecurityToken(header, payload);
            jwt = handler.WriteToken(jwtToken);

            validationParameters.IssuerSigningKey = validateKey;
            validationParameters.RequireSignedTokens = true;
            validatedSecurityToken = null;
            cp = handler.ValidateToken(jwt, validationParameters, out validatedSecurityToken);

            TestUtilities.AssertFailIfErrors("CreateAndValidateTokens_MultipleX5C", errors);
        }

        [Fact(DisplayName = "CreateAndValidateTokens: EmptyToken, serialize and deserialze an empyt JWT")]
        public void EmptyToken()
        {
            JwtSecurityTokenHandler handler = new JwtSecurityTokenHandler();
            string jwt = handler.WriteToken(new JwtSecurityToken("", ""));
            JwtSecurityToken token = new JwtSecurityToken(jwt);
            Assert.True(IdentityComparer.AreEqual<JwtSecurityToken>(token, new JwtSecurityToken("", "")));
        }

#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant
        [Theory, MemberData(nameof(CreateJwtTokenDataSet))]
#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
        public void CreateAndValidateJwtTokens(CreateAndValidateParams createAndValidateParms)
        {
            var handler = new JwtSecurityTokenHandler();
            handler.InboundClaimTypeMap.Clear();
            var jwt = handler.CreateJwt(createAndValidateParms.SecurityTokenDescriptor);
            var jwtToken = new JwtSecurityToken(jwt);

            var jwtToken2 = handler.CreateToken(
                createAndValidateParms.SecurityTokenDescriptor.Issuer,
                createAndValidateParms.SecurityTokenDescriptor.Audience,
                new ClaimsIdentity(createAndValidateParms.SecurityTokenDescriptor.Claims),
                createAndValidateParms.SecurityTokenDescriptor.NotBefore,
                createAndValidateParms.SecurityTokenDescriptor.Expires,
                createAndValidateParms.SecurityTokenDescriptor.IssuedAt,
                createAndValidateParms.SecurityTokenDescriptor.SigningCredentials);
            var jwt2 = handler.WriteToken(jwtToken2);

            var jwtToken3 = handler.CreateJwtSecurityToken(createAndValidateParms.SecurityTokenDescriptor);
            var jwt3 = handler.WriteToken(jwtToken3);

            var context = new CompareContext();
            IdentityComparer.AreEqual(jwtToken, jwtToken2, context);
            TestUtilities.AssertFailIfErrors("CreateAndValidate, jwtToken, jwtToken2", context.Diffs);

            context = new CompareContext();
            IdentityComparer.AreEqual(jwtToken, jwtToken3, context);
            TestUtilities.AssertFailIfErrors("CreateAndValidate, jwtToken, jwtToken3", context.Diffs);

            Assert.Equal(jwt, jwtToken.RawData);
            Assert.Equal(jwt2, jwtToken2.RawData);
            Assert.Equal(jwt3, jwtToken3.RawData);
            Assert.Equal(jwt, jwt2);
            Assert.Equal(jwt, jwt3);
        }

        public static TheoryData<CreateAndValidateParams> CreateJwtTokenDataSet()
        {
            var createParams = new TheoryData<CreateAndValidateParams>();
            DateTime utcNow = DateTime.UtcNow;

            createParams.Add(new CreateAndValidateParams
            {
                SecurityTokenDescriptor = new SecurityTokenDescriptor
                {
                    Audience = IdentityUtilities.DefaultAudience,
                    Claims = ClaimSets.DefaultClaims,
                    Expires = utcNow + TimeSpan.FromDays(1),
                    IssuedAt = utcNow,
                    Issuer = IdentityUtilities.DefaultIssuer,
                    NotBefore = utcNow,
                    SigningCredentials = KeyingMaterial.RSASigningCreds_2048,
                },
            });

            return createParams;
        }

        [Fact(DisplayName = "CreateAndValidateTokens: RoundTripTokens")]
        public void RoundTripTokens()
        {
            JwtSecurityTokenHandler handler = new JwtSecurityTokenHandler();
            var nbf = DateTime.UtcNow;
            var expires = nbf + TimeSpan.FromDays(1);

            var createAndValidateParams = new CreateAndValidateParams
            {
                Case = "ClaimSets.DuplicateTypes",
                CompareTo = IdentityUtilities.CreateJwtSecurityToken(
                    IdentityUtilities.DefaultIssuer, 
                    IdentityUtilities.DefaultAudience, 
                    ClaimSets.OutboundClaimTypeTransform(ClaimSets.DuplicateTypes(IdentityUtilities.DefaultIssuer, IdentityUtilities.DefaultIssuer), 
                    JwtSecurityTokenHandler.DefaultOutboundClaimTypeMap), nbf, expires, nbf, null),
                ExceptionType = null,
                SecurityTokenDescriptor = new SecurityTokenDescriptor
                {
                    Audience = IdentityUtilities.DefaultAudience,
                    Claims = ClaimSets.OutboundClaimTypeTransform(ClaimSets.DuplicateTypes(IdentityUtilities.DefaultIssuer, IdentityUtilities.DefaultAudience), JwtSecurityTokenHandler.DefaultOutboundClaimTypeMap),
                    Expires = expires,
                    IssuedAt = nbf,
                    Issuer = IdentityUtilities.DefaultIssuer,
                    NotBefore = nbf,
                },
                TokenValidationParameters = new TokenValidationParameters
                {
                    RequireSignedTokens = false,
                    ValidateAudience = false,
                    ValidateLifetime = false,
                    ValidateIssuer = false,
                }
            };

            RunRoundTrip(createAndValidateParams, handler);
            SigningCredentials signingCredentials = new SigningCredentials(KeyingMaterial.X509SecurityKeySelfSigned2048_SHA256, SecurityAlgorithms.RsaSha256Signature);
            X509SecurityKey verifyingKey = KeyingMaterial.X509SecurityKeySelfSigned2048_SHA256_Public;
            createAndValidateParams = new CreateAndValidateParams
            {
                Case = "ClaimSets.Simple_simpleSigned_Asymmetric",
                CompareTo = IdentityUtilities.CreateJwtSecurityToken(
                    IdentityUtilities.DefaultIssuer,
                    IdentityUtilities.DefaultAudience,
                    ClaimSets.OutboundClaimTypeTransform(ClaimSets.Simple(IdentityUtilities.DefaultIssuer, IdentityUtilities.DefaultIssuer),
                    JwtSecurityTokenHandler.DefaultOutboundClaimTypeMap), nbf, expires, nbf, signingCredentials),
                ExceptionType = null,
                SecurityTokenDescriptor = new SecurityTokenDescriptor
                {
                    Audience = IdentityUtilities.DefaultAudience,
                    Claims = ClaimSets.OutboundClaimTypeTransform(ClaimSets.Simple(IdentityUtilities.DefaultIssuer, IdentityUtilities.DefaultAudience), JwtSecurityTokenHandler.DefaultOutboundClaimTypeMap),
                    Expires = expires,
                    IssuedAt = nbf,
                    Issuer = IdentityUtilities.DefaultIssuer,
                    NotBefore = nbf,
                    SigningCredentials = signingCredentials
                },
                TokenValidationParameters = new TokenValidationParameters
                {
                    IssuerSigningKey = verifyingKey,
                    ValidAudience = IdentityUtilities.DefaultAudience,
                    ValidIssuer      = IdentityUtilities.DefaultIssuer,
                }
            };

            RunRoundTrip(createAndValidateParams, handler);

            createAndValidateParams = new CreateAndValidateParams
            {
                Case = "ClaimSets.Simple_simpleSigned_Symmetric",
                CompareTo = IdentityUtilities.CreateJwtSecurityToken(IdentityUtilities.DefaultIssuer, IdentityUtilities.DefaultAudience, 
                ClaimSets.OutboundClaimTypeTransform(ClaimSets.Simple(IdentityUtilities.DefaultIssuer, IdentityUtilities.DefaultIssuer), JwtSecurityTokenHandler.DefaultOutboundClaimTypeMap), 
                nbf, expires, nbf, KeyingMaterial.DefaultSymmetricSigningCreds_256_Sha2),
                ExceptionType = null,
                SecurityTokenDescriptor = new SecurityTokenDescriptor
                {
                    Claims = ClaimSets.Simple(IdentityUtilities.DefaultIssuer, IdentityUtilities.DefaultIssuer),
                    SigningCredentials = KeyingMaterial.DefaultSymmetricSigningCreds_256_Sha2,
                    Expires = expires,
                    IssuedAt = nbf,
                    NotBefore = nbf,
                    Issuer = IdentityUtilities.DefaultIssuer,
                    Audience = IdentityUtilities.DefaultAudience
                },
                TokenValidationParameters = new TokenValidationParameters
                {
                    ValidAudience = IdentityUtilities.DefaultAudience,
                    IssuerSigningKey = KeyingMaterial.DefaultSymmetricSecurityKey_256,
                    ValidIssuer = IdentityUtilities.DefaultIssuer,
                }
            };

            RunRoundTrip(createAndValidateParams, handler);
        }

        private void RunRoundTrip(CreateAndValidateParams createandValidateParams, JwtSecurityTokenHandler handler)
        {
            SecurityToken validatedToken;
            string jwt = handler.WriteToken(createandValidateParams.CompareTo);
            ClaimsPrincipal principal = handler.ValidateToken(jwt, createandValidateParams.TokenValidationParameters, out validatedToken);

            // create from security descriptor
            SecurityTokenDescriptor tokenDescriptor = createandValidateParams.SecurityTokenDescriptor;
            JwtSecurityToken token = handler.CreateToken(
                issuer: tokenDescriptor.Issuer,
                audience: tokenDescriptor.Audience,
                expires: tokenDescriptor.Expires,
                notBefore: tokenDescriptor.NotBefore,
                issuedAt: tokenDescriptor.IssuedAt,
                subject: new ClaimsIdentity(tokenDescriptor.Claims),
                signingCredentials: createandValidateParams.SecurityTokenDescriptor.SigningCredentials ) as JwtSecurityToken;

            CompareContext context = new CompareContext();
            IdentityComparer.AreEqual(token, createandValidateParams.CompareTo, context);
            TestUtilities.AssertFailIfErrors("!IdentityComparer.AreEqual( token, jwtParams.CompareTo )", context.Diffs);
        }

        [Fact(DisplayName = "CreateAndValidateTokens: DuplicateClaims - roundtrips with duplicate claims")]
        public void DuplicateClaims()
        {
            SecurityToken validatedToken;
            string encodedJwt = IdentityUtilities.CreateJwtSecurityToken(
                new SecurityTokenDescriptor
                { 
                    Audience = IdentityUtilities.DefaultAudience,
                    Claims = ClaimSets.DuplicateTypes(IdentityUtilities.DefaultIssuer, IdentityUtilities.DefaultIssuer),
                    Issuer = IdentityUtilities.DefaultIssuer,
                    SigningCredentials = IdentityUtilities.DefaultAsymmetricSigningCredentials
                });

            JwtSecurityTokenHandler tokenHandler = new JwtSecurityTokenHandler();
            tokenHandler.InboundClaimFilter.Add("aud");
            tokenHandler.InboundClaimFilter.Add("exp");
            tokenHandler.InboundClaimFilter.Add("iat");
            tokenHandler.InboundClaimFilter.Add("iss");
            tokenHandler.InboundClaimFilter.Add("nbf");

            ClaimsPrincipal claimsPrincipal = tokenHandler.ValidateToken(encodedJwt, IdentityUtilities.DefaultAsymmetricTokenValidationParameters, out validatedToken);

            var context = new CompareContext { IgnoreProperties = true, IgnoreSubject = true };
            if (!IdentityComparer.AreEqual<IEnumerable<Claim>>(claimsPrincipal.Claims, ClaimSets.DuplicateTypes(IdentityUtilities.DefaultIssuer, IdentityUtilities.DefaultIssuer), context))
                TestUtilities.AssertFailIfErrors("CreateAndValidateTokens: DuplicateClaims - roundtrips with duplicate claims", context.Diffs);

            tokenHandler.InboundClaimFilter.Clear();
        }

        [Fact(DisplayName = "CreateAndValidateTokens: JsonClaims - claims values are objects serailized as json, can be recognized and reconstituted.")]
        public void RunJsonClaims()
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
            var context = CompareContext.Default;
            context.Title = "1";
            if (!IdentityComparer.AreEqual
                (claimsPrincipal.Identity as ClaimsIdentity,
                 JsonClaims.ClaimsIdentityDistributedClaims(issuer, TokenValidationParameters.DefaultAuthenticationType, JsonClaims.ClaimSources, JsonClaims.ClaimNames),
                 context))
            {
                errors.Add("JsonClaims.ClaimSources, JsonClaims.ClaimNames: test failed");
                errors.AddRange(context.Diffs);
            };

            Claim c = claimsPrincipal.FindFirst(claimSources);
            if (!c.Properties.ContainsKey(JwtSecurityTokenHandler.JsonClaimTypeProperty))
            {
                errors.Add(claimSources + " claim, did not have json property: " + JwtSecurityTokenHandler.JsonClaimTypeProperty);
            }
            else
            {
                if (!string.Equals(c.Properties[JwtSecurityTokenHandler.JsonClaimTypeProperty], "Newtonsoft.Json.Linq.JProperty", StringComparison.Ordinal))
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

            TestUtilities.AssertFailIfErrors("CreateAndValidateTokens_JsonClaims", errors);
        }

        [Fact(DisplayName = "This test ensures that claims with the 'role' and 'roles' are mapped to ClaimTypes.Role.")]
        public void RoleClaims()
        {
            JwtSecurityTokenHandler handler = new JwtSecurityTokenHandler();
            TokenValidationParameters validationParameters = new TokenValidationParameters
            {
                RequireSignedTokens = false,
                ValidateAudience = false,
                ValidateIssuer = false
            };

            DateTime utcNow = DateTime.UtcNow;
            DateTime expire = utcNow + TimeSpan.FromHours(1);
            ClaimsIdentity subject = new ClaimsIdentity(claims: ClaimSets.RoleClaimsShortType());
            JwtSecurityToken jwtToken = handler.CreateToken(IdentityUtilities.DefaultIssuer, IdentityUtilities.DefaultAudience, subject, utcNow, expire, utcNow) as JwtSecurityToken;

            SecurityToken securityToken;
            ClaimsPrincipal principal = handler.ValidateToken(jwtToken.RawData, validationParameters, out securityToken);
            CheckForRoles(new string[] { "role1", "roles1" }, new string[] { "notrole1", "notrole2" }, principal);
            ClaimsIdentity expectedIdentity =
                new ClaimsIdentity(
                    authenticationType: "Federation",
                    claims: ClaimSets.RoleClaimsLongType()
                    );

            expectedIdentity.AddClaim(new Claim(JwtRegisteredClaimNames.Iss, IdentityUtilities.DefaultIssuer, ClaimValueTypes.String, IdentityUtilities.DefaultIssuer));
            expectedIdentity.AddClaim(new Claim(JwtRegisteredClaimNames.Aud, IdentityUtilities.DefaultAudience, ClaimValueTypes.String, IdentityUtilities.DefaultIssuer));

            Claim claim = new Claim(JwtRegisteredClaimNames.Exp, EpochTime.GetIntDate(expire).ToString(), "JSON", IdentityUtilities.DefaultIssuer);
            claim.Properties.Add(JwtSecurityTokenHandler.JsonClaimTypeProperty, "System.Int64");
            expectedIdentity.AddClaim(claim);

            claim = new Claim(JwtRegisteredClaimNames.Nbf, EpochTime.GetIntDate(utcNow).ToString(), "JSON", IdentityUtilities.DefaultIssuer);
            claim.Properties.Add(JwtSecurityTokenHandler.JsonClaimTypeProperty, "System.Int64");
            expectedIdentity.AddClaim(claim);

            claim = new Claim(JwtRegisteredClaimNames.Iat, EpochTime.GetIntDate(utcNow).ToString(), "JSON", IdentityUtilities.DefaultIssuer);
            claim.Properties.Add(JwtSecurityTokenHandler.JsonClaimTypeProperty, "System.Int64");
            expectedIdentity.AddClaim(claim);

            CompareContext context = new CompareContext();
            IdentityComparer.AreEqual<IEnumerable<Claim>>(principal.Claims, expectedIdentity.Claims, context);
            TestUtilities.AssertFailIfErrors("RoleClaims", context.Diffs);
        }

        private static string NameClaimTypeDelegate(SecurityToken jwt, string issuer)
        {
            return _nameClaimTypeForDelegate;
        }

        private static string RoleClaimTypeDelegate(SecurityToken jwt, string issuer)
        {
            return _roleClaimTypeForDelegate;
        }

        [Fact(DisplayName = "CreateAndValidateTokens: NameAndRoleClaimDelegates - name and role type delegates.")]
        public void NameAndRoleClaimDelegates()
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
                IssuerSigningKey = KeyingMaterial.DefaultX509Key_2048,
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
                IssuerSigningKey = KeyingMaterial.DefaultX509Key_2048,
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
            Assert.Equal(identity.NameClaimType, expectedNameClaimType);
            Assert.Equal(identity.RoleClaimType, expectedRoleClaimType);
            Assert.True(principal.IsInRole(roles[0]));
            for (int i = 1; i < roles.Length; i++)
            {
                Assert.False(principal.IsInRole(roles[i]));
            }

            Assert.Equal(identity.Name, names[0]);
            for (int i = 1; i < names.Length; i++)
            {
                Assert.NotEqual(identity.Name, names[i]);
            }
        }

        /// <summary>
        /// First role is expected, others are not.
        /// </summary>
        /// <param name="names"></param>
        /// <param name="roles"></param>
        private void CheckForRoles(string[] expectedRoles, string[] unexpectedRoles, ClaimsPrincipal principal, string expectedRoleClaimType = ClaimsIdentity.DefaultRoleClaimType)
        {
            ClaimsIdentity identity = principal.Identity as ClaimsIdentity;
            Assert.Equal(identity.RoleClaimType, expectedRoleClaimType);
            for (int i = 1; i < expectedRoles.Length; i++)
            {
                Assert.True(principal.IsInRole(expectedRoles[i]));
            }

            for (int i = 1; i < unexpectedRoles.Length; i++)
            {
                Assert.False(principal.IsInRole(unexpectedRoles[i]));
            }
        }
    }
}
