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
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

namespace Microsoft.IdentityModel.Tokens.Tests
{
    /// <summary>
    /// Returns default token creation / validation artifacts:
    /// Claim
    /// ClaimIdentity
    /// ClaimPrincipal
    /// SecurityTokenDescriptor
    /// TokenValidationParameters
    /// </summary>
    public static class Default
    {
        public static string ActorIssuer
        {
            get { return "http://Default.ActorIssuer.com/Actor"; }
        }

        public static string AuthenticationType
        {
            get { return "Default.Federation"; }
        }

        public static string Acr
        {
            get { return "Default.Acr"; }
        }

        public static string Amr
        {
            get { return "Default.Amr"; }
        }

        public static List<string> Amrs
        {
            get { return new List<string> { "Default.Amr1", "Default.Amr2", "Default.Amr3", "Default.Amr4" };
            }
        }

        public static string Audience
        {
            get { return "http://Default.Audience.com"; }
        }

        public static List<string> Audiences
        {
            get
            {
                return new List<string>
                { "http://Default.Audience1.com",
                  "http://Default.Audience2.com",
                  "http://Default.Audience3.com",
                  "http://Default.Audience4.com"
                };
            }
        }

        public static string AsymmetricJwt
        {
            get { return Jwt(SecurityTokenDescriptor(KeyingMaterial.DefaultX509SigningCreds_2048_RsaSha2_Sha2)); }
        }

        public static SecurityTokenDescriptor AsymmetricSignSecurityTokenDescriptor(List<Claim> claims)
        {
            return SecurityTokenDescriptor(null, AsymmetricSigningCredentials, claims);
        }

        public static SigningCredentials AsymmetricSigningCredentials
        {
            get { return new SigningCredentials(KeyingMaterial.DefaultX509SigningCreds_2048_RsaSha2_Sha2.Key, KeyingMaterial.DefaultX509SigningCreds_2048_RsaSha2_Sha2.Algorithm); }
        }

        public static SignatureProvider AsymmetricSignatureProvider
        {
            get { return CryptoProviderFactory.Default.CreateForSigning(KeyingMaterial.DefaultX509Key_2048, SecurityAlgorithms.RsaSha256); }
        }

        public static SecurityKey AsymmetricSigningKey
        {
            get { return new X509SecurityKey(KeyingMaterial.DefaultCert_2048); }
        }

        public static TokenValidationParameters AsymmetricEncryptSignTokenValidationParameters
        {
            get { return TokenValidationParameters(SymmetricEncryptionKey256, AsymmetricSigningKey); }
        }

        public static TokenValidationParameters AsymmetricSignTokenValidationParameters
        {
            get { return TokenValidationParameters(null, AsymmetricSigningKey); }
        }

        public static string Azp
        {
            get { return "http://Default.Azp.com"; }
        }

        public static string ClaimsIdentityLabel
        {
            get { return "Default.ClaimsIdentityLabel"; }
        }

        public static string ClaimsIdentityLabelDup
        {
            get { return "Default.ClaimsIdentityLabelDup"; }
        }

        public static ClaimsPrincipal ClaimsPrincipal
        {
            get { return new ClaimsPrincipal(ClaimSets.DefaultClaimsIdentity); }
        }

        public static string Issuer
        {
            get { return "http://Default.Issuer.com"; }
        }

        public static string Jwt(SecurityTokenDescriptor tokenDescriptor)
        {
            return (new JwtSecurityTokenHandler()).CreateEncodedJwt(tokenDescriptor);
        }

        public static string NameClaimType
        {
            get { return "Default.NameClaimType"; }
        }

        public static string OriginalIssuer
        {
            get { return "http://Default.OriginalIssuer.com"; }
        }

        public static string RoleClaimType
        {
            get { return "Default.RoleClaimType"; }
        }

        public static SecurityTokenDescriptor SecurityTokenDescriptor()
        {
            return SecurityTokenDescriptor(SymmetricEncryptingCredentials, SymmetricSigningCredentials, ClaimSets.DefaultClaims);
        }

        public static SecurityTokenDescriptor SecurityTokenDescriptor(EncryptingCredentials encryptingCredentials)
        {
            return SecurityTokenDescriptor(encryptingCredentials, null, null);
        }

        public static SecurityTokenDescriptor SecurityTokenDescriptor(EncryptingCredentials encryptingCredentials, SigningCredentials signingCredentials, List<Claim> claims)
        {
            return new SecurityTokenDescriptor
            {
                Audience = Audience,
                EncryptingCredentials = encryptingCredentials,
                Expires = DateTime.UtcNow + TimeSpan.FromDays(1),
                Issuer = Issuer,
                IssuedAt = DateTime.UtcNow,
                NotBefore = DateTime.UtcNow,
                SigningCredentials = signingCredentials,
                Subject = claims == null ? ClaimSets.DefaultClaimsIdentity : new ClaimsIdentity(claims)
            };
        }

        public static SecurityTokenDescriptor SecurityTokenDescriptor(SigningCredentials signingCredentials)
        {
            return SecurityTokenDescriptor(null, signingCredentials, null);
        }

        public static string Subject
        {
            get { return "Default.Subject"; }
        }

        public static EncryptingCredentials SymmetricEncryptingCredentials
        {
            get
            {
                return new EncryptingCredentials(
                    KeyingMaterial.DefaultSymmetricEncryptingCreds_Aes128_Sha2.Key,
                    KeyingMaterial.DefaultSymmetricEncryptingCreds_Aes128_Sha2.Alg,
                    KeyingMaterial.DefaultSymmetricEncryptingCreds_Aes128_Sha2.Enc);
            }
        }

        public static SymmetricSecurityKey SymmetricEncryptionKey128
        {
            get
            {
                return new SymmetricSecurityKey(KeyingMaterial.DefaultSymmetricSecurityKey_128.Key)
                {
                    KeyId = KeyingMaterial.DefaultSymmetricSecurityKey_128.KeyId
                };
            }
        }

        public static SymmetricSecurityKey SymmetricEncryptionKey128_2
        {
            get
            {
                return new SymmetricSecurityKey(KeyingMaterial.SymmetricSecurityKey2_128.Key)
                {
                    KeyId = KeyingMaterial.SymmetricSecurityKey2_128.KeyId
                };
            }
        }

        public static SymmetricSecurityKey SymmetricEncryptionKey256
        {
            get
            {
                return new SymmetricSecurityKey(KeyingMaterial.DefaultSymmetricSecurityKey_256.Key)
                {
                    KeyId = KeyingMaterial.DefaultSymmetricSecurityKey_256.KeyId
                };
            }
        }

        public static SymmetricSecurityKey SymmetricEncryptionKey256_2
        {
            get
            {
                return new SymmetricSecurityKey(KeyingMaterial.SymmetricSecurityKey2_256.Key)
                {
                    KeyId = KeyingMaterial.SymmetricSecurityKey2_256.KeyId
                };
            }
        }

        public static SymmetricSecurityKey SymmetricEncryptionKey384
        {
            get
            {
                return new SymmetricSecurityKey(KeyingMaterial.DefaultSymmetricSecurityKey_384.Key)
                {
                    KeyId = KeyingMaterial.DefaultSymmetricSecurityKey_384.KeyId
                };
            }
        }

        public static SymmetricSecurityKey SymmetricEncryptionKey512
        {
            get
            {
                return new SymmetricSecurityKey(KeyingMaterial.DefaultSymmetricSecurityKey_512.Key)
                {
                    KeyId = KeyingMaterial.DefaultSymmetricSecurityKey_512.KeyId
                };
            }
        }
        public static SymmetricSecurityKey SymmetricEncryptionKey768
        {
            get
            {
                return new SymmetricSecurityKey(KeyingMaterial.DefaultSymmetricSecurityKey_768.Key)
                {
                    KeyId = KeyingMaterial.DefaultSymmetricSecurityKey_768.KeyId
                };
            }
        }

        public static SymmetricSecurityKey SymmetricEncryptionKey1024
        {
            get
            {
                return new SymmetricSecurityKey(KeyingMaterial.DefaultSymmetricSecurityKey_1024.Key)
                {
                    KeyId = KeyingMaterial.DefaultSymmetricSecurityKey_1024.KeyId
                };
            }
        }

        public static string SymmetricJwe
        {
            get { return Jwt(SecurityTokenDescriptor(KeyingMaterial.DefaultSymmetricEncryptingCreds_Aes128_Sha2)); }
        }

        public static string SymmetricJws
        {
            get { return Jwt(SecurityTokenDescriptor(KeyingMaterial.DefaultSymmetricSigningCreds_256_Sha2)); }
        }

        public static SecurityTokenDescriptor SymmetricEncryptSignSecurityTokenDescriptor()
        {
            return SecurityTokenDescriptor(SymmetricEncryptingCredentials, SymmetricSigningCredentials, ClaimSets.DefaultClaims);
        }

        public static SecurityTokenDescriptor SymmetricSignSecurityTokenDescriptor(List<Claim> claims)
        {
            return SecurityTokenDescriptor(null, SymmetricSigningCredentials, claims);
        }

        public static SigningCredentials SymmetricSigningCredentials
        {
            get
            {
                return new SigningCredentials(
                    KeyingMaterial.DefaultSymmetricSigningCreds_256_Sha2.Key,
                    KeyingMaterial.DefaultSymmetricSigningCreds_256_Sha2.Algorithm);
            }
        }

        public static SymmetricSecurityKey SymmetricSigningKey56
        {
            get
            {
                return new SymmetricSecurityKey(KeyingMaterial.DefaultSymmetricSecurityKey_56.Key) { KeyId = KeyingMaterial.DefaultSymmetricSecurityKey_56.KeyId };
            }
        }
        public static SymmetricSecurityKey SymmetricSigningKey64
        {
            get
            {
                return new SymmetricSecurityKey(KeyingMaterial.DefaultSymmetricSecurityKey_64.Key) { KeyId = KeyingMaterial.DefaultSymmetricSecurityKey_64.KeyId };
            }
        }

        public static SymmetricSecurityKey SymmetricSigningKey128
        {
            get
            {
                return new SymmetricSecurityKey(KeyingMaterial.DefaultSymmetricSecurityKey_128.Key) { KeyId = KeyingMaterial.DefaultSymmetricSecurityKey_128.KeyId };
            }
        }

        public static SymmetricSecurityKey SymmetricSigningKey256
        {
            get
            {
                return new SymmetricSecurityKey(KeyingMaterial.DefaultSymmetricSecurityKey_256.Key) { KeyId = KeyingMaterial.DefaultSymmetricSecurityKey_256.KeyId };
            }
        }

        public static SymmetricSecurityKey SymmetricSigningKey384
        {
            get
            {
                return new SymmetricSecurityKey(KeyingMaterial.DefaultSymmetricSecurityKey_384.Key) { KeyId = KeyingMaterial.DefaultSymmetricSecurityKey_384.KeyId };
            }
        }

        public static SymmetricSecurityKey SymmetricSigningKey512
        {
            get
            {
                return new SymmetricSecurityKey(KeyingMaterial.DefaultSymmetricSecurityKey_512.Key) { KeyId = KeyingMaterial.DefaultSymmetricSecurityKey_512.KeyId };
            }
        }

        public static SymmetricSecurityKey SymmetricSigningKey768
        {
            get
            {
                return new SymmetricSecurityKey(KeyingMaterial.DefaultSymmetricSecurityKey_768.Key) { KeyId = KeyingMaterial.DefaultSymmetricSecurityKey_768.KeyId };
            }
        }

        public static SymmetricSecurityKey SymmetricSigningKey1024
        {
            get
            {
                return new SymmetricSecurityKey(KeyingMaterial.DefaultSymmetricSecurityKey_1024.Key) { KeyId = KeyingMaterial.DefaultSymmetricSecurityKey_1024.KeyId };
            }
        }

        public static TokenValidationParameters SymmetricEncyptSignTokenValidationParameters
        {
            get { return TokenValidationParameters(SymmetricEncryptionKey256, SymmetricSigningKey256); }
        }

        public static TokenValidationParameters SymmetricEncyptSignInfiniteLifetimeTokenValidationParameters
        {
            get
            {
                TokenValidationParameters parameters = TokenValidationParameters(SymmetricEncryptionKey256, SymmetricSigningKey256);
                parameters.ValidateLifetime = false;
                return parameters;
            }
        }

        public static TokenValidationParameters TokenValidationParameters(SecurityKey encryptionKey, SecurityKey signingKey)
        {
            return new TokenValidationParameters
            {
                AuthenticationType = AuthenticationType,
                TokenDecryptionKey = encryptionKey,
                IssuerSigningKey = signingKey,
                ValidAudience = Audience,
                ValidIssuer = Issuer,
            };
        }
    }
}
