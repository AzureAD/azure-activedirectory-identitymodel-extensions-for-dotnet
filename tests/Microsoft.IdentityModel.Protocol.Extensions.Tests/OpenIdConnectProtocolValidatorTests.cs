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

using Microsoft.IdentityModel.Protocols;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens;
using System.Security.Claims;

namespace Microsoft.IdentityModel.Test
{
    /// <summary>
    /// 
    /// </summary>
    [TestClass]
    public class OpenIdConnectProtocolValidatorTests
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
        [TestProperty("TestCaseID", "e905d825-a3ff-4461-a5a4-46d842d0c4ba")]
        [Description("Tests: Validate")]
        public void OpenIdConnectProtocolValidator_Validate()
        {
            JwtSecurityToken jwt =  new JwtSecurityToken();
            OpenIdConnectProtocolValidationContext validationContext = new OpenIdConnectProtocolValidationContext();

            // jwt null
            Validate(jwt: null, validationContext: null, ee: ExpectedException.ArgumentNullException());

            // validationContext null
            Validate(jwt: jwt, validationContext: null, ee: ExpectedException.ArgumentNullException());

            // aud missing
            Validate(jwt: jwt, validationContext: validationContext, ee: new ExpectedException(typeExpected: typeof(OpenIdConnectProtocolException), substringExpected: "IDX10309:"));

            // exp missing
            jwt.Payload.AddClaim(new Claim(JwtRegisteredClaimNames.Aud, IdentityUtilities.DefaultAudience));
            Validate(jwt: jwt, validationContext: validationContext, ee: new ExpectedException(typeExpected: typeof(OpenIdConnectProtocolException), substringExpected: "IDX10309:"));

            // iat missing
            jwt.Payload.AddClaim(new Claim(JwtRegisteredClaimNames.Exp, EpochTime.GetIntDate(DateTime.UtcNow).ToString()));
            Validate(jwt: jwt, validationContext: validationContext, ee: new ExpectedException(typeExpected: typeof(OpenIdConnectProtocolException), substringExpected: "IDX10309:"));

            // iss missing
            jwt.Payload.AddClaim(new Claim(JwtRegisteredClaimNames.Iat, EpochTime.GetIntDate(DateTime.UtcNow).ToString()));
            Validate(jwt: jwt, validationContext: validationContext, ee: new ExpectedException(typeExpected: typeof(OpenIdConnectProtocolException), substringExpected: "IDX10309:"));

            // sub missing
            jwt.Payload.AddClaim(new Claim(JwtRegisteredClaimNames.Iss, IdentityUtilities.DefaultIssuer));
            Validate(jwt: jwt, validationContext: validationContext, ee: new ExpectedException(typeExpected: typeof(OpenIdConnectProtocolException), substringExpected: "IDX10309:"));

            // nonce invalid 
            string validNonce = OpenIdConnectProtocolValidator.GenerateNonce();

            // add the valid 'nonce' but set validationContext.Nonce to a different 'nonce'.
            jwt.Payload.AddClaim(new Claim(JwtRegisteredClaimNames.Nonce, validNonce));
            jwt.Payload.AddClaim(new Claim(JwtRegisteredClaimNames.Sub, "sub"));
            validationContext.Nonce = OpenIdConnectProtocolValidator.GenerateNonce();
            Validate(jwt: jwt, validationContext: validationContext, ee: new ExpectedException(typeExpected: typeof(OpenIdConnectProtocolInvalidNonceException), substringExpected: "IDX10301:"));

            // authorizationCode invalid
            string validAuthorizationCode = OpenIdConnectProtocolValidator.GenerateNonce();
            string validChash = IdentityUtilities.CreateCHash(validAuthorizationCode, "SHA256");

            JwtSecurityToken jwtWithSignatureChash =
                new JwtSecurityToken
                (
                    audience: IdentityUtilities.DefaultAudience,
                    claims: new List<Claim> 
                    { 
                        new Claim(JwtRegisteredClaimNames.CHash, validChash),
                        new Claim(JwtRegisteredClaimNames.Iat, EpochTime.GetIntDate(DateTime.UtcNow).ToString()),
                        new Claim(JwtRegisteredClaimNames.Nonce, validNonce),
                        new Claim(JwtRegisteredClaimNames.Sub, "sub"),
                    },
                    expires: DateTime.UtcNow + TimeSpan.FromHours(1),
                    issuer: IdentityUtilities.DefaultIssuer,
                    signingCredentials: IdentityUtilities.DefaultAsymmetricSigningCredentials
                );

            validationContext.OpenIdConnectProtocolValidationParameters.AlgorithmMap = 
                new Dictionary<string, string>
                {
                    {JwtAlgorithms.RSA_SHA256, "SHA256"}
                };
            validationContext.Nonce = validNonce;
            validationContext.AuthorizationCode = validNonce;
            Validate(jwt: jwtWithSignatureChash, validationContext: validationContext, ee: new ExpectedException(typeExpected: typeof(OpenIdConnectProtocolInvalidCHashException), substringExpected: "IDX10304:"));

            // nonce and authorizationCode valid
            validationContext.AuthorizationCode = validAuthorizationCode;
            Validate(jwt: jwtWithSignatureChash, validationContext: validationContext, ee: ExpectedException.NoExceptionExpected);

            // validate optional claims
            validationContext.OpenIdConnectProtocolValidationParameters.RequireAcr = true;
            Validate(jwt: jwtWithSignatureChash, validationContext: validationContext, ee: new ExpectedException(typeExpected: typeof(OpenIdConnectProtocolException), substringExpected: "IDX10312:"));
            jwtWithSignatureChash.Payload.AddClaim(new Claim(JwtRegisteredClaimNames.Acr, "acr"));

            validationContext.OpenIdConnectProtocolValidationParameters.RequireAmr = true;
            Validate(jwt: jwtWithSignatureChash, validationContext: validationContext, ee: new ExpectedException(typeExpected: typeof(OpenIdConnectProtocolException), substringExpected: "IDX10313:"));
            jwtWithSignatureChash.Payload.AddClaim(new Claim(JwtRegisteredClaimNames.Amr, "amr"));

            validationContext.OpenIdConnectProtocolValidationParameters.RequireAuthTime = true;
            Validate(jwt: jwtWithSignatureChash, validationContext: validationContext, ee: new ExpectedException(typeExpected: typeof(OpenIdConnectProtocolException), substringExpected: "IDX10314:"));
            jwtWithSignatureChash.Payload.AddClaim(new Claim(JwtRegisteredClaimNames.AuthTime, "authTime"));

            validationContext.OpenIdConnectProtocolValidationParameters.RequireAzp = true;
            Validate(jwt: jwtWithSignatureChash, validationContext: validationContext, ee: new ExpectedException(typeExpected: typeof(OpenIdConnectProtocolException), substringExpected: "IDX10315:"));
            jwtWithSignatureChash.Payload.AddClaim(new Claim(JwtRegisteredClaimNames.Azp, "azp"));

            Validate(jwt: jwtWithSignatureChash, validationContext: validationContext, ee: ExpectedException.NoExceptionExpected);
        }

        public void Validate(JwtSecurityToken jwt, OpenIdConnectProtocolValidationContext validationContext, ExpectedException ee)
        {
            try
            {
                OpenIdConnectProtocolValidator.Validate(jwt, validationContext);
                ee.ProcessNoException();
            }
            catch (Exception ex)
            {
                ee.ProcessException(ex);
            }
        }

        [TestMethod]
        [TestProperty("TestCaseID", "9a082558-f87e-4ae0-be80-852fbcf869d4")]
        [Description("Tests: Validation of CHash")]
        public void OpenIdConnectProtocolValidator_CHash()
        {

            string authorizationCode1 = OpenIdConnectProtocolValidator.GenerateNonce();
            string authorizationCode2 = OpenIdConnectProtocolValidator.GenerateNonce();

            string chash1 = IdentityUtilities.CreateCHash(authorizationCode1, "SHA256");
            string chash2 = IdentityUtilities.CreateCHash(authorizationCode2, "SHA256");

            Dictionary<string, string> emptyDictionary = new Dictionary<string, string>();
            Dictionary<string, string> mappedDictionary =
                new Dictionary<string, string>
                {
                    {JwtAlgorithms.RSA_SHA256, "SHA256"}
                };

            JwtSecurityToken jwtWithCHash =
                new JwtSecurityToken
                (
                    audience: IdentityUtilities.DefaultAudience,
                    claims: new List<Claim> { new Claim(JwtRegisteredClaimNames.CHash, chash1) },
                    issuer: IdentityUtilities.DefaultIssuer
                );

            JwtSecurityToken jwtWithEmptyCHash =
                new JwtSecurityToken
                (
                    audience: IdentityUtilities.DefaultAudience,
                    claims: new List<Claim> { new Claim(JwtRegisteredClaimNames.CHash, string.Empty) },
                    issuer: IdentityUtilities.DefaultIssuer
                );

            JwtSecurityToken jwtWithoutCHash =
                new JwtSecurityToken
                (
                    audience: IdentityUtilities.DefaultAudience,
                    claims: new List<Claim> { new Claim(JwtRegisteredClaimNames.Nonce, chash2) },
                    issuer: IdentityUtilities.DefaultIssuer                    
                );

            JwtSecurityToken jwtWithSignatureChash1 = 
                new JwtSecurityToken
                (
                    audience : IdentityUtilities.DefaultAudience,
                    claims: new List<Claim> { new Claim(JwtRegisteredClaimNames.CHash, chash1) },
                    issuer: IdentityUtilities.DefaultIssuer,
                    signingCredentials : IdentityUtilities.DefaultAsymmetricSigningCredentials
                );

            JwtSecurityToken jwtWithSignatureMultipleChashes =
                new JwtSecurityToken
                (
                    audience: IdentityUtilities.DefaultAudience,
                    claims: new List<Claim> { new Claim(JwtRegisteredClaimNames.CHash, chash1), new Claim(JwtRegisteredClaimNames.CHash, chash2) },
                    issuer: IdentityUtilities.DefaultIssuer,
                    signingCredentials: IdentityUtilities.DefaultAsymmetricSigningCredentials
                );

            // chash is not a string, but array
            ValidateCHash(jwt: jwtWithSignatureMultipleChashes, authorizationCode: authorizationCode2, algorithmMap: mappedDictionary, ee: new ExpectedException(typeExpected: typeof(OpenIdConnectProtocolInvalidCHashException), substringExpected: "IDX10302:"));

            // chash doesn't match
            ValidateCHash(jwt: jwtWithSignatureChash1, authorizationCode: authorizationCode2, algorithmMap: mappedDictionary, ee: new ExpectedException(typeExpected: typeof(OpenIdConnectProtocolInvalidCHashException), substringExpected: "IDX10304:"));

            // use algorithm map
            ValidateCHash(jwt: jwtWithSignatureChash1, authorizationCode: authorizationCode1, algorithmMap: mappedDictionary, ee: ExpectedException.NoExceptionExpected);

            // Creation of algorithm failed, need to map.
            ValidateCHash(jwt: jwtWithSignatureChash1, authorizationCode: authorizationCode1, algorithmMap: null, ee: new ExpectedException(typeExpected: typeof(OpenIdConnectProtocolInvalidCHashException), substringExpected: "IDX10306:"));

            ValidateCHash(jwt: null, authorizationCode: null, algorithmMap: null, ee: ExpectedException.ArgumentNullException());
            ValidateCHash(jwt: jwtWithCHash, authorizationCode: null, algorithmMap: null, ee: ExpectedException.ArgumentNullException());
            ValidateCHash(jwt: jwtWithoutCHash, authorizationCode: authorizationCode1, algorithmMap: null, ee: new ExpectedException(typeExpected: typeof(OpenIdConnectProtocolInvalidCHashException)));
            ValidateCHash(jwt: jwtWithEmptyCHash, authorizationCode: authorizationCode1, algorithmMap: null, ee: new ExpectedException(typeExpected: typeof(OpenIdConnectProtocolInvalidCHashException), substringExpected: "IDX10303:"));
            ValidateCHash(jwt: jwtWithCHash, authorizationCode: authorizationCode1, algorithmMap: null, ee: new ExpectedException(typeExpected: typeof(OpenIdConnectProtocolInvalidCHashException)));

        }

        private void ValidateCHash(JwtSecurityToken jwt, string authorizationCode, IDictionary<string, string> algorithmMap, ExpectedException ee)
        {
            try
            {
                OpenIdConnectProtocolValidator.ValidateCHash(jwt, authorizationCode, algorithmMap);
                ee.ProcessNoException();
            }
            catch(Exception ex)
            {
                ee.ProcessException(ex);
            }

            return;
        }

        [TestMethod]
        [TestProperty("TestCaseID", "9a082558-f87e-4ae0-be80-852fbcf869d4")]
        [Description("Tests: Validation of Nonce")]
        public void OpenIdConnectProtocolValidator_ValidateNonce()
        {
            string nonce1 = OpenIdConnectProtocolValidator.GenerateNonce();
            string nonce2 = OpenIdConnectProtocolValidator.GenerateNonce();

            JwtSecurityToken jwtWithNonce =
                new JwtSecurityToken
                (
                    IdentityUtilities.DefaultIssuer,
                    IdentityUtilities.DefaultAudience,
                    new List<Claim> { new Claim(JwtRegisteredClaimNames.Nonce, nonce1) }
                );

            JwtSecurityToken jwtWithoutNonce =
                new JwtSecurityToken
                (
                    IdentityUtilities.DefaultIssuer,
                    IdentityUtilities.DefaultAudience,
                    new List<Claim> { new Claim(JwtRegisteredClaimNames.NameId, nonce1) }
                );

            ValidateNonce(jwt: null, nonce: null, ee: ExpectedException.ArgumentNullException());
            ValidateNonce(jwt: jwtWithNonce,  nonce: null, ee: ExpectedException.ArgumentNullException());
            ValidateNonce(jwt: jwtWithNonce, nonce: nonce2, ee: new ExpectedException(typeof(OpenIdConnectProtocolInvalidNonceException)));
            ValidateNonce(jwt: jwtWithoutNonce, nonce: nonce2, ee: new ExpectedException(typeof(OpenIdConnectProtocolInvalidNonceException)));
            ValidateNonce(jwt: jwtWithNonce, nonce: nonce1, ee: ExpectedException.NoExceptionExpected);
        }

        private void ValidateNonce(JwtSecurityToken jwt, string nonce, ExpectedException ee)
        {
            try
            {
                OpenIdConnectProtocolValidator.ValidateNonce(jwt, nonce);
                ee.ProcessNoException();
            }
            catch(Exception ex)
            {
                ee.ProcessException(ex);
            }
        }

        private static string GetHashAlgorithm(string algorithm)
        {
            switch (algorithm)
            {
                case JwtAlgorithms.ECDSA_SHA256:
                case JwtAlgorithms.RSA_SHA256:
                case JwtAlgorithms.HMAC_SHA256:
                    return "SHA256";

                case JwtAlgorithms.ECDSA_SHA384:
                case JwtAlgorithms.RSA_SHA384:
                case JwtAlgorithms.HMAC_SHA384:
                    return "SHA384";

                case JwtAlgorithms.ECDSA_SHA512:
                case JwtAlgorithms.RSA_SHA512:
                case JwtAlgorithms.HMAC_SHA512:
                    return "SHA512";

                default:
                    return "SHA256";
            }
        }
    }
}