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

using System;
using System.Collections.Generic;
using System.IdentityModel.Test;
using System.IdentityModel.Tokens;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Xml;
using IMSaml2TokenHandler = Microsoft.IdentityModel.Tokens.Saml2SecurityTokenHandler;
using IMSamlTokenHandler = Microsoft.IdentityModel.Tokens.SamlSecurityTokenHandler;


namespace Microsoft.IdentityModel.Test
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
            HashAlgorithm hashAlgorithm = HashAlgorithm.Create(algorithm);
            byte[] hashBytes = hashAlgorithm.ComputeHash(Encoding.UTF8.GetBytes(authorizationCode));
            return Base64UrlEncoder.Encode(hashBytes, 0, hashBytes.Length / 2);
        }

        public static string CreateJwtToken(SecurityTokenDescriptor tokenDescriptor)
        {
            return CreateJwtToken(tokenDescriptor, new JwtSecurityTokenHandler());
        }

        public static string CreateJwtToken(SecurityTokenDescriptor securityTokenDescriptor, SecurityTokenHandler tokenHandler)
        {
            return tokenHandler.WriteToken(tokenHandler.CreateToken(securityTokenDescriptor));
        }

        public static JwtSecurityToken CreateJwtSecurityToken(string issuer = null, string originalIssuer = null)
        {
            string iss = issuer ?? IdentityUtilities.DefaultIssuer;
            string originalIss = originalIssuer ?? IdentityUtilities.DefaultOriginalIssuer;

            return new JwtSecurityToken(issuer, "http://www.contoso.com", ClaimSets.Simple(iss, originalIss));
        }

        public static JwtSecurityToken CreateJwtSecurityToken()
        {
            return CreateJwtSecurityToken(IdentityUtilities.DefaultAsymmetricSecurityTokenDescriptor) as JwtSecurityToken;
        }

        public static JwtSecurityToken CreateJwtSecurityToken(SecurityTokenDescriptor tokenDescriptor)
        {
            return (new JwtSecurityTokenHandler()).CreateToken(tokenDescriptor) as JwtSecurityToken;
        }

        public static JwtSecurityToken CreateJwtSecurityToken(string issuer, string originalIssuer, IEnumerable<Claim> claims, SigningCredentials signingCredentials)
        {
            JwtPayload payload = new JwtPayload(issuer, "urn:uri", claims, DateTime.UtcNow, DateTime.UtcNow + TimeSpan.FromHours(10));
            JwtHeader header = new JwtHeader(signingCredentials);
            return new JwtSecurityToken(header, payload);
        }

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

        public const string DefaultAuthenticationType = "Federation";

        public static string DefaultAudience { get { return "http://relyingparty.com"; } }
        public static IList<string> DefaultAudiences { get { return new List<string> { "http://relyingparty.com", "http://relyingparty2.com", "http://relyingparty3.com", "http://relyingparty3.com" }; } }

        public static SigningCredentials DefaultAsymmetricSigningCredentials { get { return KeyingMaterial.DefaultAsymmetricSigningCreds_2048_RsaSha2_Sha2; } }
        public static SecurityToken DefaultAsymmetricSigningToken { get { return KeyingMaterial.DefaultAsymmetricX509Token_2048; ; } }

        public static IEnumerable<Claim> DefaultClaims 
        { 
            get 
            {
                return new List<Claim>()
                {
                    new Claim(ClaimTypes.Country, "USA", ClaimValueTypes.String, DefaultIssuer, DefaultIssuer),
                    new Claim(ClaimTypes.Email, "user@contoso.com", ClaimValueTypes.String, DefaultIssuer, DefaultIssuer),
                    new Claim(ClaimTypes.GivenName, "Tony", ClaimValueTypes.String, DefaultIssuer, DefaultIssuer),
                    new Claim(ClaimTypes.HomePhone, "555.1212", ClaimValueTypes.String, DefaultIssuer, DefaultIssuer),
                    new Claim(ClaimTypes.Role, "Sales", ClaimValueTypes.String, DefaultIssuer, DefaultIssuer),
                };
            }
        }
        
        public static ClaimsIdentity DefaultClaimsIdentity 
        { 
            get 
            {
                return new ClaimsIdentity(DefaultClaims, DefaultAuthenticationType); 
            }
        }

        public static ClaimsPrincipal DefaultClaimsPrincipal 
        { 
            get 
            { 
                return new ClaimsPrincipal(DefaultClaimsIdentity); 
            } 
        }

        public const string DefaultIssuer = "http://gotjwt.com";
        public const string DefaultOriginalIssuer = "http://gotjwt.com/Original";

        public static SigningCredentials DefaultSymmetricSigningCredentials { get { return KeyingMaterial.DefaultSymmetricSigningCreds_256_Sha2; } }
        public static SecurityToken DefaultSymmetricSigningToken { get { return KeyingMaterial.DefaultSymmetricSecurityToken_256; ; } }
        public static string DefaultAsymmetricJwt
        {
            get { return DefaultJwt(DefaultAsymmetricSecurityTokenDescriptor); }
        }

        public static string DefaultSymmetricJwt
        {
            get { return DefaultJwt(DefaultSymmetricSecurityTokenDescriptor); }
        }

        public static string DefaultJwt(SecurityTokenDescriptor securityTokenDescriptor)
        {
            JwtSecurityTokenHandler tokenHandler = new JwtSecurityTokenHandler();
            return tokenHandler.WriteToken(tokenHandler.CreateToken(securityTokenDescriptor));
        }

        public static SecurityTokenDescriptor DefaultAsymmetricSecurityTokenDescriptor
        {
            get { return DefaultSecurityTokenDescriptor(DefaultAsymmetricSigningCredentials); }
        }

        public static SecurityTokenDescriptor DefaultSymmetricSecurityTokenDescriptor
        {
            get { return DefaultSecurityTokenDescriptor(DefaultSymmetricSigningCredentials); }
        }

        public static SecurityTokenDescriptor DefaultSecurityTokenDescriptor(SigningCredentials signingCredentials)
        {
            return new SecurityTokenDescriptor
            {
                AppliesToAddress = DefaultAudience,
                SigningCredentials = signingCredentials,
                Subject = DefaultClaimsIdentity,
                TokenIssuerName = DefaultIssuer,
                Lifetime = new System.IdentityModel.Protocols.WSTrust.Lifetime(DateTime.UtcNow, DateTime.UtcNow + TimeSpan.FromDays(1)),
            };
        }

        public static TokenValidationParameters DefaultAsymmetricTokenValidationParameters
        {
            get { return DefaultTokenValidationParameters(DefaultAsymmetricSigningToken); }
        }

        public static TokenValidationParameters NullLifetimeAsymmetricTokenValidationParameters
        {
            get { return NullLifetimeTokenValidationParameters(DefaultAsymmetricSigningToken); }
        }

        public static TokenValidationParameters DefaultSymmetricTokenValidationParameters
        {
            get { return DefaultTokenValidationParameters(DefaultSymmetricSigningToken); }
        }

        public static TokenValidationParameters DefaultTokenValidationParameters(SecurityToken securityToken)
        {
            return new TokenValidationParameters
            {
                AuthenticationType = DefaultAuthenticationType,
                IssuerSigningToken = securityToken,
                ValidAudience = DefaultAudience,
                ValidIssuer = DefaultIssuer,
            };
        }

        public static TokenValidationParameters NullLifetimeTokenValidationParameters(SecurityToken securityToken)
        {
            return new TokenValidationParameters
            {
                AuthenticationType = DefaultAuthenticationType,
                IssuerSigningToken = securityToken,
                ValidAudience = DefaultAudience,
                ValidIssuer = DefaultIssuer,
                RequireExpirationTime = false,
            };
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
        public static SecurityToken NotDefaultSigningToken = KeyingMaterial.DefaultX509Token_2048;
        
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

        public const string NullIssuer = null;

        public static TokenValidationParameters GetNullIssuerAsymmetricTokenValidationParameters(bool isValidIssuer)
        {
            return NullIssuerTokenValidationParameters(DefaultAsymmetricSigningToken, isValidIssuer);
        }

        public static TokenValidationParameters NullIssuerTokenValidationParameters(SecurityToken securityToken, bool isValidIssuer)
        {
            return new TokenValidationParameters
            {
                AuthenticationType = DefaultAuthenticationType,
                IssuerSigningToken = securityToken,
                ValidAudience = DefaultAudience,
                ValidIssuer = NullIssuer,
                ValidateIssuer = isValidIssuer,
            };
        }

        public static SecurityTokenDescriptor NullLifetimeAsymmetricSecurityTokenDescriptor
        {
            get { return NullLifetimeSecurityTokenDescriptor(DefaultAsymmetricSigningCredentials); }
        }

        public static SecurityTokenDescriptor NullIssuerAsymmetricSecurityTokenDescriptor
        {
            get { return NullIssuerSecurityTokenDescriptor(DefaultAsymmetricSigningCredentials); }
        }

        public static SecurityTokenDescriptor NullIssuerSecurityTokenDescriptor(SigningCredentials signingCredentials)
        {
            return new SecurityTokenDescriptor
            {
                AppliesToAddress = DefaultAudience,
                SigningCredentials = signingCredentials,
                Subject = DefaultClaimsIdentity,
                TokenIssuerName = NullIssuer,
                Lifetime = new System.IdentityModel.Protocols.WSTrust.Lifetime(DateTime.UtcNow, DateTime.UtcNow + TimeSpan.FromDays(1)),
            };
        }

        public static SecurityTokenDescriptor NullLifetimeSecurityTokenDescriptor(SigningCredentials signingCredentials)
        {
            return new SecurityTokenDescriptor
            {
                AppliesToAddress = DefaultAudience,
                SigningCredentials = signingCredentials,
                Subject = DefaultClaimsIdentity,
                TokenIssuerName = DefaultIssuer,
                Lifetime = new System.IdentityModel.Protocols.WSTrust.Lifetime(null, null),
            };
        }

    }
}