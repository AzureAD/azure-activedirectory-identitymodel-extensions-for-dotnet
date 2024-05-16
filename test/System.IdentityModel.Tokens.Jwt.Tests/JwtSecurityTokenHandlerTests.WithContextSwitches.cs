// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

﻿using System.Security.Claims;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.TestUtils;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace System.IdentityModel.Tokens.Jwt.Tests
{
    [Collection(nameof(JwtSecurityTokenHandlerNonParallelRunTests))]
    public class JwtSecurityTokenHandlerTestsWithContextSwitches
    {
        [Fact]
        public void JwtSecurityTokenHandler_CreateToken_AddShortFormMappingForRsaOAEPEnabled()
        {
            AppContext.SetSwitch(X509EncryptingCredentials._useShortNameForRsaOaepKey, true);
            var encryptingCredentials = new X509EncryptingCredentials(Default.Certificate);
            SecurityTokenDescriptor tokenDescriptor = new SecurityTokenDescriptor
            {
                Issuer = Default.Issuer,
                IssuedAt = DateTime.UtcNow.Subtract(new TimeSpan(1, 0, 0)),
                Subject = new ClaimsIdentity(Default.PayloadJsonClaims),
                NotBefore = DateTime.UtcNow.Subtract(new TimeSpan(1, 0, 0)),
                Expires = DateTime.UtcNow.Subtract(new TimeSpan(0, 10, 0)),
                SigningCredentials = Default.AsymmetricSigningCredentials,
                EncryptingCredentials = encryptingCredentials,
                TokenType = "JWE"
            };

            JwtSecurityTokenHandler tokenHandler = new JwtSecurityTokenHandler();
            JwtSecurityToken token = tokenHandler.CreateJwtSecurityToken(tokenDescriptor);

            Assert.NotNull(token);
            Assert.NotEqual(token.Header.Alg, SecurityAlgorithms.RsaOaepKeyWrap);
            Assert.Equal(token.Header.Alg, SecurityAlgorithms.RsaOAEP);
        }

        [Fact]
        public void JwtSecurityTokenHandler_CreateToken_AddShortFormMappingForRsaOAEPDisabled()
        {
            AppContext.SetSwitch(X509EncryptingCredentials._useShortNameForRsaOaepKey, false);
            var encryptingCredentials = new X509EncryptingCredentials(Default.Certificate);
            SecurityTokenDescriptor tokenDescriptor = new SecurityTokenDescriptor
            {
                Issuer = Default.Issuer,
                IssuedAt = DateTime.UtcNow.Subtract(new TimeSpan(1, 0, 0)),
                Subject = new ClaimsIdentity(Default.PayloadJsonClaims),
                NotBefore = DateTime.UtcNow.Subtract(new TimeSpan(1, 0, 0)),
                Expires = DateTime.UtcNow.Subtract(new TimeSpan(0, 10, 0)),
                SigningCredentials = Default.AsymmetricSigningCredentials,
                EncryptingCredentials = encryptingCredentials,
                TokenType = "JWE"
            };

            JwtSecurityTokenHandler tokenHandler = new JwtSecurityTokenHandler();
            JwtSecurityToken token = tokenHandler.CreateJwtSecurityToken(tokenDescriptor);

            Assert.NotNull(token);
            Assert.NotEqual(token.Header.Alg, SecurityAlgorithms.RsaOAEP);
            Assert.Equal(token.Header.Alg, SecurityAlgorithms.RsaOaepKeyWrap);
        }

        [Fact]
        public void JsonWebTokenHandler_CreateToken_AddShortFormMappingForRsaOAEPEnabled()
        {
            AppContext.SetSwitch(X509EncryptingCredentials._useShortNameForRsaOaepKey, true);
            var encryptingCredentials = new X509EncryptingCredentials(Default.Certificate);
            SecurityTokenDescriptor tokenDescriptor = new SecurityTokenDescriptor
            {
                Issuer = Default.Issuer,
                IssuedAt = DateTime.UtcNow.Subtract(new TimeSpan(1, 0, 0)),
                Subject = new ClaimsIdentity(Default.PayloadJsonClaims),
                NotBefore = DateTime.UtcNow.Subtract(new TimeSpan(1, 0, 0)),
                Expires = DateTime.UtcNow.Subtract(new TimeSpan(0, 10, 0)),
                SigningCredentials = Default.AsymmetricSigningCredentials,
                EncryptingCredentials = encryptingCredentials,
                TokenType = "JWE"
            };

            JsonWebTokenHandler tokenHandler = new JsonWebTokenHandler();
            var token = tokenHandler.CreateToken(tokenDescriptor);
            JsonWebToken jsonToken = tokenHandler.ReadToken(token) as JsonWebToken;

            Assert.NotNull(jsonToken);
            Assert.NotEqual(jsonToken._alg, SecurityAlgorithms.RsaOaepKeyWrap);
            Assert.Equal(jsonToken._alg, SecurityAlgorithms.RsaOAEP);
        }

        [Fact]
        public void JsonWebTokenHandler_CreateToken_AddShortFormMappingForRsaOAEPDisabled()
        {
            AppContext.SetSwitch(X509EncryptingCredentials._useShortNameForRsaOaepKey, false);
            var encryptingCredentials = new X509EncryptingCredentials(Default.Certificate);
            SecurityTokenDescriptor tokenDescriptor = new SecurityTokenDescriptor
            {
                Issuer = Default.Issuer,
                IssuedAt = DateTime.UtcNow.Subtract(new TimeSpan(1, 0, 0)),
                Subject = new ClaimsIdentity(Default.PayloadJsonClaims),
                NotBefore = DateTime.UtcNow.Subtract(new TimeSpan(1, 0, 0)),
                Expires = DateTime.UtcNow.Subtract(new TimeSpan(0, 10, 0)),
                SigningCredentials = Default.AsymmetricSigningCredentials,
                EncryptingCredentials = encryptingCredentials,
                TokenType = "JWE"
            };

            JsonWebTokenHandler tokenHandler = new JsonWebTokenHandler();
            var token = tokenHandler.CreateToken(tokenDescriptor);
            JsonWebToken jsonToken = tokenHandler.ReadToken(token) as JsonWebToken;

            Assert.NotNull(jsonToken);
            Assert.Equal(jsonToken._alg, SecurityAlgorithms.RsaOaepKeyWrap);
            Assert.NotEqual(jsonToken._alg, SecurityAlgorithms.RsaOAEP);
        }
    }
}
