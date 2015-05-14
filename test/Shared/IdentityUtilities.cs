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

using System.Collections.Generic;
using System.IdentityModel.Tokens;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

#if SAML
using IMSaml2TokenHandler = Microsoft.IdentityModel.Tokens.Saml2SecurityTokenHandler;
using IMSamlTokenHandler = Microsoft.IdentityModel.Tokens.SamlSecurityTokenHandler;
#endif

namespace System.IdentityModel.Test
{
    /// <summary>
    /// Main purpose of this code is to serve up Identities
    /// ClaimPrincipal
    /// ClaimIdentiy
    /// Claim
    /// SamlTokens
    /// JwtTokens
    /// </summary>
    public static class IdentityUtilities
    {
        /// <summary>
        /// Computes the CHash per 
        /// </summary>
        /// <param name="authorizationCode"></param>
        /// <param name="algorithm"></param>
        /// <returns></returns>
        public static string CreateCHash(string authorizationCode, string algorithm)
        {
            HashAlgorithm hashAlgorithm = null;
            switch (algorithm)
            {
                case "SHA1":
                    hashAlgorithm = SHA1.Create();
                    break;
                case "SHA256":
                    hashAlgorithm = SHA256.Create();
                    break;
                case "SHA384":
                    hashAlgorithm = SHA384.Create();
                    break;
                case "SHA512":
                    hashAlgorithm = SHA512.Create();
                    break;
                default:
                    throw new ArgumentOutOfRangeException("Hash algorithm not known: " + algorithm);
            }

            byte[] hashBytes = hashAlgorithm.ComputeHash(Encoding.UTF8.GetBytes(authorizationCode));
            return Base64UrlEncoder.Encode(hashBytes, 0, hashBytes.Length / 2);
        }

        public static JwtSecurityToken CreateJwtSecurityToken(string issuer = null, string originalIssuer = null)
        {
            string iss = issuer ?? IdentityUtilities.DefaultIssuer;
            string originalIss = originalIssuer ?? IdentityUtilities.DefaultOriginalIssuer;

            return new JwtSecurityToken(issuer, "http://www.contoso.com", ClaimSets.Simple(iss, originalIss));
        }

        public static string CreateJwtSecurityToken(SecurityTokenDescriptor tokenDescriptor)
        {
            var handler = new JwtSecurityTokenHandler();
            return handler.WriteToken(handler.CreateToken(
                issuer: tokenDescriptor.Issuer,
                audience: tokenDescriptor.Audience,
                expires: tokenDescriptor.Expires,
                notBefore: tokenDescriptor.NotBefore,
                signingCredentials: tokenDescriptor.SigningCredentials,
                subject: new ClaimsIdentity(tokenDescriptor.Claims)
                ) as JwtSecurityToken);
        }

        public static JwtSecurityToken CreateJwtSecurityToken(string issuer, string originalIssuer, IEnumerable<Claim> claims, SigningCredentials signingCredentials)
        {
            JwtPayload payload = new JwtPayload(issuer, "urn:uri", claims, DateTime.UtcNow, DateTime.UtcNow + TimeSpan.FromHours(10));
            JwtHeader header = new JwtHeader(signingCredentials);
            return new JwtSecurityToken(header, payload);
        }

#if INCLUDE_SAML
        public static string CreateSaml2Token()
        {
            return CreateSaml2Token(DefaultAsymmetricSecurityTokenDescriptor);
        }

        public static string CreateSaml2Token(SecurityTokenDescriptor securityTokenDescriptor)
        {
            return CreateSaml2Token(securityTokenDescriptor, new IMSaml2TokenHandler());
        }

        public static string CreateSaml2Token(SecurityTokenDescriptor securityTokenDescriptor, SecurityTokenHandler tokenHandler)
        {
            return CreateToken(securityTokenDescriptor, tokenHandler);
        }

        public static SamlSecurityToken CreateSamlSecurityToken()
        {
            return CreateSamlSecurityToken(DefaultAsymmetricSecurityTokenDescriptor, new IMSamlTokenHandler());
        }

        public static SamlSecurityToken CreateSamlSecurityToken(SecurityTokenDescriptor securityTokenDescriptor, SecurityTokenHandler tokenHandler)
        {
            return CreateSecurityToken(securityTokenDescriptor, tokenHandler) as SamlSecurityToken;
        }

        public static SecurityToken CreateSecurityToken(SecurityTokenDescriptor securityTokenDescriptor, SecurityTokenHandler tokenHandler)
        {
            return tokenHandler.CreateToken(securityTokenDescriptor);
        }

        public static string CreateSamlToken()
        {
            return CreateSamlToken(DefaultAsymmetricSecurityTokenDescriptor);
        }

        public static string CreateSamlToken(SecurityTokenDescriptor securityTokenDescriptor)
        {
            return CreateToken(securityTokenDescriptor, new IMSamlTokenHandler());
        }

        public static string CreateSamlToken(SecurityTokenDescriptor securityTokenDescriptor, SecurityTokenHandler tokenHandler)
        {
            return CreateToken(securityTokenDescriptor, tokenHandler);
        }

        public static string CreateToken(SecurityTokenDescriptor securityTokenDescriptor, SecurityTokenHandler tokenHandler)
        {
            SecurityToken securityToken = tokenHandler.CreateToken(securityTokenDescriptor);
            StringBuilder sb = new StringBuilder();
            XmlWriter writer = XmlWriter.Create(sb);
            tokenHandler.WriteToken(writer, securityToken);
            writer.Flush();
            writer.Close();
            return sb.ToString();
        }
#endif
        public const string DefaultAuthenticationType = "Federation";

        public static string DefaultAudience { get { return "http://relyingparty.com"; } }
        public static IList<string> DefaultAudiences { get { return new List<string> { "http://relyingparty.com", "http://relyingparty2.com", "http://relyingparty3.com", "http://relyingparty3.com" }; } }

        public static SigningCredentials DefaultAsymmetricSigningCredentials { get { return KeyingMaterial.DefaultX509SigningCreds_2048_RsaSha2_Sha2; } }
        public static SecurityKey DefaultAsymmetricSigningKey { get { return KeyingMaterial.DefaultX509Key_2048; } }
        
        public static ClaimsPrincipal DefaultClaimsPrincipal 
        { 
            get 
            { 
                return new ClaimsPrincipal(ClaimSets.DefaultClaimsIdentity); 
            } 
        }

        public const string DefaultIssuer = "http://gotjwt.com";
        public const string DefaultOriginalIssuer = "http://gotjwt.com/Original";

        public static string DefaultAsymmetricJwt
        {
            get { return DefaultJwt(DefaultSecurityTokenDescriptor(KeyingMaterial.DefaultX509SigningCreds_2048_RsaSha2_Sha2)); }
        }

        public const string NotDefaultAudience = "http://notrelyingparty.com";
        public static IEnumerable<Claim> NotDefaultClaims
        {
            get
            {
                return new List<Claim>()
                {
                    new Claim(ClaimTypes.Country, "USA", ClaimValueTypes.String, NotDefaultIssuer, NotDefaultOriginalIssuer),
                    new Claim(ClaimTypes.Email, "user@contoso.com", ClaimValueTypes.String, NotDefaultIssuer, NotDefaultOriginalIssuer),
                    new Claim(ClaimTypes.GivenName, "Tony", ClaimValueTypes.String, NotDefaultIssuer, NotDefaultOriginalIssuer),
                    new Claim(ClaimTypes.HomePhone, "555.1212", ClaimValueTypes.String, NotDefaultIssuer, NotDefaultOriginalIssuer),
                    new Claim(ClaimTypes.Role, "Sales", ClaimValueTypes.String, NotDefaultIssuer, NotDefaultOriginalIssuer),
                };
            }
        }

        public static ClaimsIdentity NotDefaultClaimsIdentity
        {
            get
            {
                return new ClaimsIdentity(NotDefaultClaims); 
            }
        }

        public const string NotDefaultIssuer = "http://notgotjwt.com";
        public const string NotDefaultOriginalIssuer = "http://notgotjwt.com/Original";
        public static SigningCredentials NotDefaultSigningCredentials = KeyingMaterial.DefaultX509SigningCreds_2048_RsaSha2_Sha2;
        public static SecurityKey NotDefaultSigningKey = KeyingMaterial.RsaSecurityKey_2048;


#if SymmetricKeySuport
        public static string DefaultSymmetricJwt
        {
            get { return DefaultJwt(KeyingMaterial.DefaulgSymmetricSecurityKey); }
        }
#endif

public static string DefaultJwt(SecurityTokenDescriptor securityTokenDescriptor)
        {
            JwtSecurityTokenHandler tokenHandler = new JwtSecurityTokenHandler();

            return tokenHandler.WriteToken(
                tokenHandler.CreateToken(
                    audience: securityTokenDescriptor.Audience,
                    expires: securityTokenDescriptor.Expires,
                    notBefore: securityTokenDescriptor.NotBefore,
                    issuer: securityTokenDescriptor.Issuer,
                    subject: new ClaimsIdentity(securityTokenDescriptor.Claims),
                    signingCredentials: securityTokenDescriptor.SigningCredentials                    
                    ));
        }


        public static SecurityTokenDescriptor DefaultSecurityTokenDescriptor(SigningCredentials signingCredentials)
        {
            return new SecurityTokenDescriptor
            {
                Audience = DefaultAudience,
                SigningCredentials = signingCredentials,
                Claims = ClaimSets.DefaultClaims,
                Issuer = DefaultIssuer,
                IssuedAt = DateTime.UtcNow,
                Expires = DateTime.UtcNow + TimeSpan.FromDays(1),
            };
        }

        public static TokenValidationParameters DefaultAsymmetricTokenValidationParameters
        {
            get { return DefaultTokenValidationParameters(DefaultAsymmetricSigningKey); }
        }

#if SymmetricKeySuport
        public static TokenValidationParameters DefaultSymmetricTokenValidationParameters
        {
            get { return DefaultTokenValidationParameters(KeyingMaterial.DefaultSymmetricSigningKey); }
        }
#endif
        public static TokenValidationParameters DefaultTokenValidationParameters(SecurityKey key)
        {
            return new TokenValidationParameters
            {
                AuthenticationType = DefaultAuthenticationType,
                IssuerSigningKey = key,
                ValidAudience = DefaultAudience,
                ValidIssuer = DefaultIssuer,
            };
        }
        
        public static bool AudienceValidatorReturnsTrue(IEnumerable<string> audiences, SecurityToken token, TokenValidationParameters validationParameters)
        {
            return true;
        }

        public static bool AudienceValidatorThrows(IEnumerable<string> audiences, SecurityToken token, TokenValidationParameters validationParameters)
        {
            throw new SecurityTokenInvalidAudienceException("AudienceValidatorThrows");
        }

        public static string IssuerValidatorEcho(string issuer, SecurityToken token, TokenValidationParameters validationParameters)
        {
            return issuer;
        }

        public static string IssuerValidatorThrows(string issuer, SecurityToken token, TokenValidationParameters validationParameters)
        {
            throw new SecurityTokenInvalidIssuerException("IssuerValidatorThrows");
        }

        public static bool LifetimeValidatorReturnsTrue(DateTime? expires, DateTime? notBefore, SecurityToken token, TokenValidationParameters validationParameters)
        {
            return true;
        }

        public static bool LifetimeValidatorThrows(DateTime? expires, DateTime? notBefore, SecurityToken token, TokenValidationParameters validationParameters)
        {
            throw new SecurityTokenInvalidLifetimeException("LifetimeValidatorThrows");
        }        
    }
}