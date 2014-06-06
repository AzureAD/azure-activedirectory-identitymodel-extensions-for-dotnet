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
using System.Collections.Generic;
using System.IdentityModel.Tokens;
using System.Security.Claims;

namespace System.IdentityModel.Test
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

    public static class JwtTestTokens
    {
        public static JwtSecurityToken Simple(string issuer = null, string originalIssuer = null)
        {
            string iss = issuer ?? IdentityUtilities.DefaultIssuer;
            string originalIss = originalIssuer ?? IdentityUtilities.DefaultOriginalIssuer;

            return new JwtSecurityToken(issuer, "http://www.contoso.com", ClaimSets.Simple(iss, originalIss));
        }

        public static JwtSecurityToken Create(string issuer, string originalIssuer, SigningCredentials signingCredentials)
        {
            JwtPayload payload = new JwtPayload(issuer, "urn:uri", ClaimSets.Simple(issuer, originalIssuer), DateTime.UtcNow, DateTime.UtcNow + TimeSpan.FromHours(10));
            JwtHeader header = new JwtHeader(signingCredentials);
            return new JwtSecurityToken(header, payload, header.Encode() + "." + payload.Encode() + ".");
        }

        public static IEnumerable<CreateAndValidateParams> All
        {
            get
            {
                string issuer = "issuer";
                string originalIssuer = "originalIssuer";

                yield return new CreateAndValidateParams
                {
                    Case = "ClaimSets.Simple_simpleSigned_Asymmetric",
                    Claims = ClaimSets.Simple(issuer, originalIssuer),
                    CompareTo = Create(issuer, originalIssuer, KeyingMaterial.DefaultX509SigningCreds_2048_RsaSha2_Sha2),
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

                yield return new CreateAndValidateParams
                {
                    Case = "ClaimSets.Simple_simpleSigned_Symmetric",
                    Claims = ClaimSets.Simple(issuer, originalIssuer),
                    CompareTo = Create(issuer, originalIssuer, KeyingMaterial.DefaultSymmetricSigningCreds_256_Sha2),
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
            }
        }

    }

}