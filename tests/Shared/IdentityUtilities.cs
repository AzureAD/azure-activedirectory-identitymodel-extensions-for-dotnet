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

namespace Microsoft.IdentityModel.Test
{
    using System.Collections.Generic;
    using System.Diagnostics.CodeAnalysis;
    using System.IdentityModel.Tokens;
    using System.Security.Claims;
    using System.Text;
    using System.Xml;

    /// <summary>
    /// Main purpose of this code is to serve up Identities
    /// ClaimPrincipal
    /// ClaimIdentiy
    /// Claim
    /// SamlTokens
    /// JwtTokens
    /// </summary>
    public class IdentityUtilities
    {
        public static string DefaultAudience { get { return "http://relyingparty.com"; } }
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

        public const string DefaultAuthenticationType = "Federation";
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
            get {return DefaultSecurityTokenDescriptor( DefaultAsymmetricSigningCredentials );}
        }

        public static SecurityTokenDescriptor DefaultSymmetricSecurityTokenDescriptor
        {
            get { return DefaultSecurityTokenDescriptor( DefaultSymmetricSigningCredentials ); }
        }

        public static SecurityTokenDescriptor DefaultSecurityTokenDescriptor(SigningCredentials signingCredentials)
        {
            return new SecurityTokenDescriptor
            {
                AppliesToAddress = DefaultAudience,
                SigningCredentials = signingCredentials,
                Subject = DefaultClaimsIdentity,
                TokenIssuerName = DefaultIssuer,
            };
        }

        public static TokenValidationParameters DefaultAsymmetricTokenValidationParameters
        {
            get { return DefaultTokenValidationParameters(DefaultAsymmetricSigningToken); }
        }

        public static TokenValidationParameters DefaultSymmetricTokenValidationParameters
        {
            get { return DefaultTokenValidationParameters(DefaultSymmetricSigningToken); }
        }

        public static TokenValidationParameters DefaultTokenValidationParameters(SecurityToken securityToken)
        {                    
            return new TokenValidationParameters
            {
                ValidAudience = DefaultAudience,
                ValidIssuer = DefaultIssuer,
                IssuerSigningToken = securityToken,
            };
        }
        
        public static string CreateJwtToken(SecurityTokenDescriptor securityTokenDescriptor)
        {
           JwtSecurityTokenHandler jwtHandler = new JwtSecurityTokenHandler();
           SecurityToken jwtToken = jwtHandler.CreateToken(securityTokenDescriptor);
           return jwtHandler.WriteToken(jwtToken);
        }

        public static string CreateSaml2Token()
        {
            return CreateSaml2Token(DefaultAsymmetricSecurityTokenDescriptor);
        }
        public static string CreateSaml2Token(SecurityTokenDescriptor securityTokenDescriptor)
        {
            Saml2SecurityTokenHandler samlSecurityTokenHandler = new Saml2SecurityTokenHandler();
            Saml2SecurityToken samlSecurityToken = samlSecurityTokenHandler.CreateToken(securityTokenDescriptor) as Saml2SecurityToken;
            StringBuilder sb = new StringBuilder();
            XmlWriter writer = XmlWriter.Create(sb);
            samlSecurityTokenHandler.WriteToken(writer, samlSecurityToken);
            writer.Flush();
            writer.Close();
            return sb.ToString();
        }
        public static string CreateSamlToken()
        {
            return CreateSamlToken(DefaultAsymmetricSecurityTokenDescriptor);
        }

        public static string CreateSamlToken(SecurityTokenDescriptor securityTokenDescriptor)
        {
            SamlSecurityTokenHandler samlSecurityTokenHandler = new SamlSecurityTokenHandler();
            SamlSecurityToken samlSecurityToken = samlSecurityTokenHandler.CreateToken(securityTokenDescriptor) as SamlSecurityToken;
            StringBuilder sb = new StringBuilder();
            XmlWriter writer = XmlWriter.Create(sb);
            samlSecurityTokenHandler.WriteToken(writer, samlSecurityToken);
            writer.Flush();
            writer.Close();
            return sb.ToString();
        }
    }
}