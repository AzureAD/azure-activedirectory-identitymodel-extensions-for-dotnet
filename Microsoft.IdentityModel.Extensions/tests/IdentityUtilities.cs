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
        private static List<Claim> _simpleClaims;
        private static ClaimsIdentity _simpleClaimsIdentity;
        private static ClaimsPrincipal _simpleClaimsPrincipal;

        public static IEnumerable<Claim> SimpleClaims(string issuer = "http://gotjwt.onmicrosoft.com", string originalIssuer = "http://gotjwt.onmicrosoft.com")
        {
            if (_simpleClaims == null)
            {
                _simpleClaims = new List<Claim>()
                    {
                        new Claim(ClaimTypes.Country, "USA", ClaimValueTypes.String, issuer, originalIssuer),
                        new Claim(ClaimTypes.Email, "user@contoso.com", ClaimValueTypes.String, issuer, originalIssuer),
                        new Claim(ClaimTypes.GivenName, "Tony", ClaimValueTypes.String, issuer, originalIssuer),
                        new Claim(ClaimTypes.HomePhone, "555.1212", ClaimValueTypes.String, issuer, originalIssuer),
                        new Claim(ClaimTypes.Role, "Sales", ClaimValueTypes.String, issuer, originalIssuer),
                    };
            }

            return _simpleClaims;
        }

        public static ClaimsIdentity SimpleClaimsIdentity
        {
            get
            {
                if (_simpleClaimsIdentity == null)
                    _simpleClaimsIdentity = new ClaimsIdentity(IdentityUtilities.SimpleClaims(), "IdentitiesUtilities");

                return _simpleClaimsIdentity;
            }
        }

        public static ClaimsPrincipal SimpleClaimsPrincipal
        {
            get
            {
                if (_simpleClaimsPrincipal == null)
                    _simpleClaimsPrincipal = new ClaimsPrincipal(IdentityUtilities.SimpleClaimsIdentity);

                return _simpleClaimsPrincipal;
            }
        }

        public const string DefaultAudience = "http://relyingparty.com";
        public static ClaimsIdentity DefaultClaimsIdentity = new ClaimsIdentity(new List<Claim> { new Claim("http://gotjwt/name", "bob") });
        public const string DefaultIssuer   = "http://gotjwt.com";
        public static SigningCredentials DefaultSigningCredentials = KeyingMaterial.AsymmetricSigningCreds_2048_RsaSha2_Sha2;
        public static SecurityToken DefaultSigningToken = KeyingMaterial.AsymmetricX509Token_2048;

        public const string NotDefaultAudience = "http://notrelyingparty.com";
        public static ClaimsIdentity NotDefaultClaimsIdentity = new ClaimsIdentity(new List<Claim> { new Claim("http://notgotjwt/name", "notbob") });
        public const string NotDefaultIssuer = "http://notgotjwt.com";
        public static SigningCredentials NotDefaultSigningCredentials = KeyingMaterial.X509SigningCreds_2048_RsaSha2_Sha2;
        public static SecurityToken NotDefaultSigningToken = KeyingMaterial.X509Token_2048;

        public static string CreateSaml2Token()
        {
            SecurityTokenDescriptor securityTokenDescriptor =
                new SecurityTokenDescriptor
                {
                    AppliesToAddress = DefaultAudience,
                    SigningCredentials = DefaultSigningCredentials,
                    Subject = DefaultClaimsIdentity,
                    TokenIssuerName = DefaultIssuer,
                };

            return CreateSaml2Token(securityTokenDescriptor);
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
            SecurityTokenDescriptor securityTokenDescriptor =
                new SecurityTokenDescriptor
                {
                    AppliesToAddress = DefaultAudience,
                    SigningCredentials = DefaultSigningCredentials,
                    Subject = DefaultClaimsIdentity,
                    TokenIssuerName = DefaultIssuer,
                };

            return CreateSamlToken(securityTokenDescriptor);
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