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

using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.IdentityModel.Tokens.Saml;
using System.IdentityModel.Tokens.Saml2;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Xml;
using System;

namespace Microsoft.IdentityModel.Tokens.Tests
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
        /// Computes the OIDC hash for a claim. Used for creating c_hash and at_hash claims
        /// </summary>
        /// <param name="item"></param>
        /// <param name="algorithm"></param>
        /// <returns></returns>
        public static string CreateHashClaim(string item, string algorithm)
        {
            HashAlgorithm hashAlgorithm = null;
            switch (algorithm)
            {
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

            byte[] hashBytes = hashAlgorithm.ComputeHash(Encoding.UTF8.GetBytes(item));
            return Base64UrlEncoder.Encode(hashBytes, 0, hashBytes.Length / 2);
        }

        public static JwtSecurityToken CreateJwtSecurityToken(string issuer = null, string originalIssuer = null)
        {
            string iss = issuer ?? DefaultIssuer;
            string originalIss = originalIssuer ?? DefaultOriginalIssuer;

            return new JwtSecurityToken(issuer, "http://www.contoso.com", ClaimSets.Simple(iss, originalIss));
        }

        public static JwtSecurityToken CreateJwtSecurityToken(string issuer, string audience, IEnumerable<Claim> claims, DateTime? nbf, DateTime? exp, DateTime? iat, SigningCredentials signingCredentials)
        {
            JwtPayload payload = new JwtPayload(issuer, audience, claims, nbf, exp, iat);
            JwtHeader header = (signingCredentials != null) ? new JwtHeader(signingCredentials) : new JwtHeader();
            return new JwtSecurityToken(header, payload, header.Base64UrlEncode(), payload.Base64UrlEncode(), "" );
        }

        public static string CreateSaml2Token()
        {
            throw new NotImplementedException();
            //return CreateSaml2Token(DefaultAsymmetricSecurityTokenDescriptor);
        }

        public static string CreateSaml2Token(SecurityTokenDescriptor securityTokenDescriptor)
        {
            return CreateSaml2Token(securityTokenDescriptor, new Saml2SecurityTokenHandler());
        }

        public static string CreateSaml2Token(SecurityTokenDescriptor securityTokenDescriptor, SecurityTokenHandler tokenHandler)
        {
            return CreateToken(securityTokenDescriptor, tokenHandler);
        }

        public static SamlSecurityToken CreateSamlSecurityToken()
        {
            throw new NotImplementedException();
            //return CreateSamlSecurityToken(DefaultAsymmetricSecurityTokenDescriptor, new Saml2SecurityTokenHandler());
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
            throw new NotImplementedException();
            //return CreateSamlToken(DefaultAsymmetricSecurityTokenDescriptor);
        }

        public static string CreateSamlToken(SecurityTokenDescriptor securityTokenDescriptor)
        {
            return CreateToken(securityTokenDescriptor, new SamlSecurityTokenHandler());
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
#if !NETCOREAPP1_0
            writer.Close();
#endif
            return sb.ToString();
        }

        public static string ActorIssuer = "http://www.GotJwt.com/Actor";
        public const string DefaultAuthenticationType = "Federation";
        public static string DefaultAcr { get { return "DefaultAuthenticationContextClass"; } }
        public static string DefaultAmr { get { return "DefaultAuthenticationMethod"; } }
        public static List<string> DefaultAmrs { get { return new List<string> { "amr1", "amr2", "amr3", "amr4" }; } }
        public static string DefaultAudience { get { return "http://relyingparty1.com"; } }
        public static List<string> DefaultAudiences { get { return new List<string> { "http://relyingparty1.com", "http://relyingparty2.com", "http://relyingparty3.com", "http://relyingparty4.com" }; } }
        public static string DefaultAuthorizedParty { get { return "http://relyingparty.azp.com"; } }
        public static SigningCredentials DefaultAsymmetricSigningCredentials = KeyingMaterial.DefaultX509SigningCreds_2048_RsaSha2_Sha2;
        public static SigningCredentials DefaultSymmetricSigningCredentials = KeyingMaterial.DefaultSymmetricSigningCreds_256_Sha2;
        public static SignatureProvider  DefaultAsymmetricSignatureProvider = CryptoProviderFactory.Default.CreateForSigning(KeyingMaterial.DefaultX509Key_2048, SecurityAlgorithms.RsaSha256);
        public static SecurityKey DefaultAsymmetricSigningKey { get { return new X509SecurityKey(KeyingMaterial.DefaultCert_2048); } }
        public static SecurityKey DefaultSymmetricSigningKey {  get { return new SymmetricSecurityKey(KeyingMaterial.DefaultSymmetricKeyBytes_256); } }
        public static ClaimsPrincipal DefaultClaimsPrincipal { get { return new ClaimsPrincipal(ClaimSets.DefaultClaimsIdentity); } }
        public const string DefaultClaimsIdentityLabel = "DefaultClaimsIdentityLabel";
        public const string DefaultClaimsIdentityLabelDup = "DefaultClaimsIdentityLabelDup";
        public const string NotDefaultAuthenticationType = "NotDefaultAuthenticationType";
        public const string NotDefaultClaimsIdentityLabel = "NotDefaultClaimsIdentityLabel";
        public const string NotDefaultLabel = "NotDefaultLabel";
        public const string NotDefaultNameClaimType = "NotDefaultNameClaimType";
        public const string NotDefaultRoleClaimType = "NotDefaultRoleClaimType";
        public const string DefaultIssuer = "http://gotjwt.com";
        public const string DefaultOriginalIssuer = "http://gotjwt.com/Original";
        public static string DefaultAsymmetricJwt {get { return DefaultJwt(DefaultSecurityTokenDescriptor(KeyingMaterial.DefaultX509SigningCreds_2048_RsaSha2_Sha2)); }}
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
            get { return new ClaimsIdentity(NotDefaultClaims); }
        }

        public const string NotDefaultIssuer = "http://notgotjwt.com";
        public const string NotDefaultOriginalIssuer = "http://notgotjwt.com/Original";
        public static SigningCredentials NotDefaultSigningCredentials = KeyingMaterial.DefaultX509SigningCreds_2048_RsaSha2_Sha2;
        public static SecurityKey NotDefaultSigningKey = KeyingMaterial.RsaSecurityKey_2048;
        public static string DefaultSubject = "DefaultSubject";
        public static string DefaultSymmetricJwt
        {
            get { return DefaultJwt(DefaultSecurityTokenDescriptor(KeyingMaterial.DefaultSymmetricSigningCreds_256_Sha2)); }
        }

        public static string DefaultJwt(SecurityTokenDescriptor tokenDescriptor)
        {
            return (new JwtSecurityTokenHandler()).CreateEncodedJwt(tokenDescriptor);
        }

        public static SecurityTokenDescriptor DefaultAsymmetricSecurityTokenDescriptor(List<Claim> claims)
        {
            var retval = DefaultSecurityTokenDescriptor(DefaultAsymmetricSigningCredentials);
            if (claims != null)
                retval.Subject = new ClaimsIdentity(claims);

            return retval;
        }
        public static SecurityTokenDescriptor DefaultSymmetricSecurityTokenDescriptor(List<Claim> claims)
        {
            var retval = DefaultSecurityTokenDescriptor(DefaultSymmetricSigningCredentials);
            if (claims != null)
                retval.Subject = new ClaimsIdentity(claims);

            return retval;
        }

        public static SecurityTokenDescriptor DefaultSecurityTokenDescriptor(SigningCredentials signingCredentials)
        {
            return new SecurityTokenDescriptor
            {
                Audience = DefaultAudience,
                Subject = ClaimSets.DefaultClaimsIdentity,
                Issuer = DefaultIssuer,
                IssuedAt = DateTime.UtcNow,
                Expires = DateTime.UtcNow + TimeSpan.FromDays(1),
                NotBefore = DateTime.UtcNow,
                SigningCredentials = signingCredentials
            };
        }

        public static TokenValidationParameters DefaultAsymmetricTokenValidationParameters
        {
            get { return DefaultTokenValidationParameters(DefaultAsymmetricSigningKey); }
        }

        public static TokenValidationParameters DefaultSymmetricTokenValidationParameters
        {
            get { return DefaultTokenValidationParameters(DefaultSymmetricSigningKey); }
        }

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
        
        public static JwtSecurityToken SignatureValidatorReturnsTokenAsIs(string token, TokenValidationParameters validationParameters)
        {
            JwtSecurityToken jwt = new JwtSecurityToken(token);
            return jwt;
        }

        public static JwtSecurityToken SignatureValidatorThrows(string token, TokenValidationParameters validationParameters)
        {
            throw new SecurityTokenInvalidSignatureException("SignatureValidatorThrows");
        }
    }
}
