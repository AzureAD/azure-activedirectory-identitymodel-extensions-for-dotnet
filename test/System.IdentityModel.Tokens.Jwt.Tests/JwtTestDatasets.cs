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
using System.IO;
using System.Net;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.TestUtils;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace System.IdentityModel.Tokens.Jwt.Tests
{

    /// <summary>
    /// JWT test datasets intended to be shared by the <see cref="JwtSecurityTokenHandler"/> and the <see cref="JsonWebTokenHandler"/>.
    /// </summary>
    public static class JwtTestDatasets
    {
        public static TheoryData<JwtTheoryData> ValidateJwsWithConfigTheoryData
        {
            get
            {
                var validConfig = new OpenIdConnectConfiguration() { TokenEndpoint = Default.Issuer + "oauth/token", Issuer = Default.Issuer };
                validConfig.SigningKeys.Add(KeyingMaterial.DefaultX509Key_2048);

                var invalidIssuerConfig = new OpenIdConnectConfiguration() { TokenEndpoint = Default.Issuer + "oauth/token", Issuer = Default.Issuer + "2" };
                invalidIssuerConfig.SigningKeys.Add(KeyingMaterial.DefaultX509Key_2048);

                var incorrectSigningKeysConfig = new OpenIdConnectConfiguration() { TokenEndpoint = Default.Issuer + "oauth/token", Issuer = Default.Issuer };
                incorrectSigningKeysConfig.SigningKeys.Add(KeyingMaterial.X509SecurityKey2);

                var requestTimedOutException = new IOException();
                requestTimedOutException.Data.Add(HttpDocumentRetriever.StatusCode, HttpStatusCode.RequestTimeout);
                requestTimedOutException.Data.Add(HttpDocumentRetriever.ResponseContent, "requestTimedOutException");

                var requestServiceUnavailableException = new IOException();
                requestServiceUnavailableException.Data.Add(HttpDocumentRetriever.StatusCode, HttpStatusCode.RequestTimeout);
                requestServiceUnavailableException.Data.Add(HttpDocumentRetriever.ResponseContent, "requestServiceUnavailableException");

                var requestNotFoundException = new IOException();
                requestNotFoundException.Data.Add(HttpDocumentRetriever.StatusCode, HttpStatusCode.NotFound);
                requestNotFoundException.Data.Add(HttpDocumentRetriever.ResponseContent, "requestNotFoundException");

                return new TheoryData<JwtTheoryData>
                {
                    new JwtTheoryData
                    {
                        TestId = nameof(Default.AsymmetricJws) + "_" + "TVPInvalid" + "_" + "ConfigValid",
                        Token = Default.AsymmetricJws,
                        ValidationParameters = new TokenValidationParameters
                        {
                            ConfigurationManager = new StaticConfigurationManager<OpenIdConnectConfiguration>(validConfig),
                            ValidateIssuerSigningKey = true,
                            RequireSignedTokens = true,
                            ValidateIssuer = true,
                            ValidateAudience = false,
                            ValidateLifetime = false,
                        },
                        ShouldSetLastKnownConfiguration = true
                    },
                    new JwtTheoryData
                    {
                        TestId = nameof(Default.AsymmetricJws) + "_" + "TVPInvalid" + "_" + "ConfigIssuerInvalid",
                        Token = Default.AsymmetricJws,
                        ValidationParameters = new TokenValidationParameters
                        {
                            ConfigurationManager = new StaticConfigurationManager<OpenIdConnectConfiguration>(invalidIssuerConfig),
                            ValidateIssuerSigningKey = true,
                            RequireSignedTokens = true,
                            ValidateIssuer = true,
                            ValidateAudience = false,
                            ValidateLifetime = false,
                        },
                        ExpectedException = ExpectedException.SecurityTokenInvalidIssuerException("IDX10260: "),
                    },
                    new JwtTheoryData
                    {
                        TestId = nameof(Default.AsymmetricJws) + "_" + "TVPInvalid" + "_" + "ConfigIssuerInvalid" + "_IssuerValidatorReturnsTrue",
                        Token = Default.AsymmetricJws,
                        ValidationParameters = new TokenValidationParameters
                        {
                            ConfigurationManager = new StaticConfigurationManager<OpenIdConnectConfiguration>(invalidIssuerConfig),
                            ValidateIssuerSigningKey = true,
                            RequireSignedTokens = true,
                            ValidateIssuer = true,
                            IssuerValidatorUsingConfiguration = (issuer, securityToken, validationParameters, configuration) => { return issuer; },
                            ValidateAudience = false,
                            ValidateLifetime = false,
                        },
                    },
                    new JwtTheoryData
                    {
                        TestId = nameof(Default.AsymmetricJws) + "_" + "TVPInvalid" + "_" + "ConfigSigningKeysInvalid",
                        Token = Default.AsymmetricJws,
                        ValidationParameters = new TokenValidationParameters
                        {
                            ConfigurationManager = new StaticConfigurationManager<OpenIdConnectConfiguration>(incorrectSigningKeysConfig),
                            ValidateIssuerSigningKey = true,
                            RequireSignedTokens = true,
                            ValidateIssuer = true,
                            ValidateAudience = false,
                            ValidateLifetime = false,
                        },
                        ExpectedException = ExpectedException.SecurityTokenSignatureKeyNotFoundException("IDX10501: "),
                    },
                    new JwtTheoryData
                    {
                        TestId = nameof(Default.AsymmetricJws) + "_" + "TVPInvalid" + "_" + "ConfigSigningKeysInvalid" + "_SigningKeyResolverValid",
                        Token = Default.AsymmetricJws,
                        ValidationParameters = new TokenValidationParameters
                        {
                            ConfigurationManager = new StaticConfigurationManager<OpenIdConnectConfiguration>(incorrectSigningKeysConfig),
                            ValidateIssuerSigningKey = true,
                            RequireSignedTokens = true,
                            ValidateIssuer = true,
                            ValidateAudience = false,
                            ValidateLifetime = false,
                            IssuerSigningKeyResolverUsingConfiguration =  (token, securityToken, kid, validationParameters, configuration) => { return new List<SecurityKey>() { KeyingMaterial.DefaultX509Key_2048 }; }
                        },
                    },
                    new JwtTheoryData
                    {
                        TestId = nameof(Default.AsymmetricJws) + "_" + "TVPInvalid" + "_" + "ConfigValid" + "_IssuerSigningKeyValidatorReturnsFalse",
                        Token = Default.AsymmetricJws,
                        ValidationParameters = new TokenValidationParameters
                        {
                            ConfigurationManager = new StaticConfigurationManager<OpenIdConnectConfiguration>(validConfig),
                            ValidateIssuerSigningKey = true,
                            RequireSignedTokens = true,
                            ValidateIssuer = true,
                            ValidateAudience = false,
                            ValidateLifetime = false,
                            IssuerSigningKeyValidatorUsingConfiguration = (securityKey, securityToken, validationParameters, configuration) => { return false; }
                        },
                        ExpectedException = ExpectedException.SecurityTokenInvalidSigningKeyException("IDX10232: ")
                    },
                    new JwtTheoryData
                    {
                        TestId = nameof(Default.AsymmetricJws) + "_" + "TVPInvalid" + "_" + "CannotObtainConfig",
                        Token = Default.AsymmetricJws,
                        ValidationParameters = new TokenValidationParameters
                        {
                            ConfigurationManager = new ConfigurationManager<OpenIdConnectConfiguration>("DoesNotExist.json", new OpenIdConnectConfigurationRetriever(), new FileDocumentRetriever()),
                            ValidateIssuerSigningKey = true,
                            RequireSignedTokens = true,
                            ValidateIssuer = true,
                            ValidateAudience = false,
                            ValidateLifetime = false,
                        },
                        ExpectedException = new ExpectedException(typeof(SecurityTokenUnableToValidateException), "IDX10516: ")
                    },
                    new JwtTheoryData
                    {
                        TestId = nameof(Default.AsymmetricJws) + "_" + "TVPValid" + "_" + "CannotObtainConfig",
                        Token = Default.AsymmetricJws,
                        ValidationParameters = new TokenValidationParameters
                        {
                            ConfigurationManager = new ConfigurationManager<OpenIdConnectConfiguration>("DoesNotExist.json", new OpenIdConnectConfigurationRetriever(), new FileDocumentRetriever()),
                            ValidateIssuerSigningKey = true,
                            RequireSignedTokens = true,
                            ValidateIssuer = true,
                            ValidateAudience = false,
                            ValidateLifetime = false,
                            IssuerSigningKey = KeyingMaterial.DefaultX509Key_2048,
                            ValidIssuer = Default.Issuer
                        },
                        ShouldSetLastKnownConfiguration = false
                    },
                };
            }
        }

        public static TheoryData<JwtTheoryData> ValidateJwsWithLastKnownGoodTheoryData
        {
            get
            {
                var validConfig = new OpenIdConnectConfiguration() { TokenEndpoint = Default.Issuer + "oauth/token", Issuer = Default.Issuer };
                validConfig.SigningKeys.Add(KeyingMaterial.DefaultX509Key_2048);

                // a special IssuerSigningKeyValidator in the tests below is set to fail if this configuration is used in order
                // to mock issuer signing key validation failure
                var validConfigKeyValidationFails = new OpenIdConnectConfiguration() { TokenEndpoint = Default.Issuer + "oauth/token", Issuer = Default.Issuer };
                validConfigKeyValidationFails.SigningKeys.Add(KeyingMaterial.DefaultX509Key_2048);

                var invalidIssuerConfig = new OpenIdConnectConfiguration() { TokenEndpoint = Default.Issuer + "oauth/token", Issuer = Default.Issuer + "2" };
                invalidIssuerConfig.SigningKeys.Add(KeyingMaterial.DefaultX509Key_2048);

                var incorrectSigningKeysConfig = new OpenIdConnectConfiguration() { TokenEndpoint = Default.Issuer + "oauth/token", Issuer = Default.Issuer };
                incorrectSigningKeysConfig.SigningKeys.Add(KeyingMaterial.X509SecurityKey2);

                var incorrectIssuerAndSigningKeysConfig = new OpenIdConnectConfiguration() { TokenEndpoint = Default.Issuer + "oauth/token", Issuer = Default.Issuer + "2" };
                incorrectIssuerAndSigningKeysConfig.SigningKeys.Add(KeyingMaterial.X509SecurityKey2);

                var incorrectSigningKeysConfigWithMatchingKid = new OpenIdConnectConfiguration() { TokenEndpoint = Default.Issuer + "oauth/token", Issuer = Default.Issuer };
                incorrectSigningKeysConfigWithMatchingKid.SigningKeys.Add(KeyingMaterial.CreateJsonWebKeyEC(JsonWebKeyECTypes.P256, Default.X509AsymmetricSigningCredentials.Key.KeyId, KeyingMaterial.P256_D, KeyingMaterial.P256_X, KeyingMaterial.P256_Y));

                var expiredSecurityTokenDescriptor = Default.X509SecurityTokenDescriptor(Default.X509AsymmetricSigningCredentials);
                expiredSecurityTokenDescriptor.NotBefore = DateTime.UtcNow + TimeSpan.FromDays(1);
                expiredSecurityTokenDescriptor.Expires = DateTime.UtcNow + System.TimeSpan.FromDays(2);
                var expiredJws = Default.Jwt(expiredSecurityTokenDescriptor);

                return new TheoryData<JwtTheoryData>
                {
                    new JwtTheoryData
                    {
                        First = true,
                        TestId = nameof(Default.AsymmetricJws) + "_" + "ConfigKeyInvalid" + "_" + "LKGValid",
                        Token = Default.AsymmetricJws,
                        ValidationParameters = new TokenValidationParameters
                        {
                            ConfigurationManager = new MockConfigurationManager<OpenIdConnectConfiguration>(incorrectSigningKeysConfig, validConfig),
                            ValidateIssuerSigningKey = true,
                            RequireSignedTokens = true,
                            ValidateIssuer = true,
                            ValidateAudience = false,
                            ValidateLifetime = false,
                        }
                    },
                    new JwtTheoryData
                    {
                        TestId = nameof(Default.AsymmetricJws) + "_" + "ConfigKeyInvalidKidMatches" + "_" + "LKGValid",
                        Token = Default.AsymmetricJws,
                        ValidationParameters = new TokenValidationParameters
                        {
                            ConfigurationManager = new MockConfigurationManager<OpenIdConnectConfiguration>(incorrectSigningKeysConfigWithMatchingKid, validConfig),
                            ValidateIssuerSigningKey = true,
                            RequireSignedTokens = true,
                            ValidateIssuer = true,
                            ValidateAudience = false,
                            ValidateLifetime = false,
                        }
                    },
                    new JwtTheoryData
                    {
                        TestId = nameof(Default.AsymmetricJws) + "_" + "ConfigKeyInvalidKeyAndIssuer" + "_" + "LKGValid",
                        Token = Default.AsymmetricJws,
                        ValidationParameters = new TokenValidationParameters
                        {
                            ConfigurationManager = new MockConfigurationManager<OpenIdConnectConfiguration>(incorrectIssuerAndSigningKeysConfig, validConfig),
                            ValidateIssuerSigningKey = true,
                            RequireSignedTokens = true,
                            ValidateIssuer = true,
                            ValidateAudience = false,
                            ValidateLifetime = false,
                        }
                    },
                    new JwtTheoryData
                    {
                        TestId = nameof(Default.AsymmetricJws) + "_" + "ConfigIssuerInvalid" + "_" + "LKGValid",
                        Token = Default.AsymmetricJws,
                        ValidationParameters = new TokenValidationParameters
                        {
                            ConfigurationManager = new MockConfigurationManager<OpenIdConnectConfiguration>(invalidIssuerConfig, validConfig),
                            ValidateIssuerSigningKey = true,
                            RequireSignedTokens = true,
                            ValidateIssuer = true,
                            ValidateAudience = false,
                            ValidateLifetime = false,
                        }
                    },
                    new JwtTheoryData
                    {
                        TestId = nameof(Default.AsymmetricJws) + "_" + "ConfigInvalid" + "_" + "IssuerSigningKeyValidationFails" + "_" + "LKGValid",
                        Token = Default.AsymmetricJws,
                        ValidationParameters = new TokenValidationParameters
                        {
                            ConfigurationManager = new MockConfigurationManager<OpenIdConnectConfiguration>(validConfigKeyValidationFails, validConfig),
                            ValidateIssuerSigningKey = true,
                            RequireSignedTokens = true,
                            ValidateIssuer = true,
                            ValidateAudience = false,
                            ValidateLifetime = false,
                            IssuerSigningKeyValidatorUsingConfiguration = (securityKey, securityToken, validationParameters, configuration) =>
                            {
                                // mock failing on issuer validation the first time
                                if (configuration == validConfigKeyValidationFails)
                                    return false;
                                else
                                    return true;
                            },
                        }
                    },
                    new JwtTheoryData
                    {
                        TestId = nameof(Default.AsymmetricJws) + "_" + "ConfigInvalid" + "_" + "ConfigKeyInvalid" + "_" + "LKGExpired",
                        Token = Default.AsymmetricJws,
                        ValidationParameters = new TokenValidationParameters
                        {
                            ConfigurationManager = new MockConfigurationManager<OpenIdConnectConfiguration>(incorrectSigningKeysConfig, validConfig) {LastKnownGoodLifetime = TimeSpan.FromMilliseconds(.1) },
                            ValidateIssuerSigningKey = true,
                            RequireSignedTokens = true,
                            ValidateIssuer = true,
                            ValidateAudience = false,
                            ValidateLifetime = false,
                        },
                        ExpectedException = new ExpectedException(typeof(SecurityTokenSignatureKeyNotFoundException))
                    },
                    new JwtTheoryData
                    {
                        TestId = nameof(Default.AsymmetricJws) + "_" + "ConfigInvalid" + "_" + "ConfigIssuerInvalid" + "_" + "LKGExpired",
                        Token = Default.AsymmetricJws,
                        ValidationParameters = new TokenValidationParameters
                        {
                            ConfigurationManager = new MockConfigurationManager<OpenIdConnectConfiguration>(invalidIssuerConfig, validConfig) {LastKnownGoodLifetime = TimeSpan.FromMilliseconds(.1) },
                            ValidateIssuerSigningKey = true,
                            RequireSignedTokens = true,
                            ValidateIssuer = true,
                            ValidateAudience = false,
                            ValidateLifetime = false,
                        },
                        ExpectedException = new ExpectedException(typeof(SecurityTokenInvalidIssuerException))
                    },
                    new JwtTheoryData
                    {
                        TestId = nameof(Default.AsymmetricJws) + "_" + "ConfigInvalid" + "_" + "ConfigKeyInvalidKidMatches" + "_" + "LKGExpired",
                        Token = Default.AsymmetricJws,
                        ValidationParameters = new TokenValidationParameters
                        {
                            ConfigurationManager = new MockConfigurationManager<OpenIdConnectConfiguration>(incorrectSigningKeysConfigWithMatchingKid, validConfig) {LastKnownGoodLifetime = TimeSpan.FromMilliseconds(.1) },
                            ValidateIssuerSigningKey = true,
                            RequireSignedTokens = true,
                            ValidateIssuer = true,
                            ValidateAudience = false,
                            ValidateLifetime = false,
                        },
                        ExpectedException = new ExpectedException(typeof(SecurityTokenInvalidSignatureException))
                    },
                    new JwtTheoryData
                    {
                        TestId = nameof(Default.AsymmetricJws) + "_" + "ConfigInvalid" + "_" + "ConfigKeyInvalidKeyAndIssuer" + "_" + "LKGExpired",
                        Token = Default.AsymmetricJws,
                        ValidationParameters = new TokenValidationParameters
                        {
                            ConfigurationManager = new MockConfigurationManager<OpenIdConnectConfiguration>(incorrectIssuerAndSigningKeysConfig, validConfig) {LastKnownGoodLifetime = TimeSpan.FromMilliseconds(.1) },
                            ValidateIssuerSigningKey = true,
                            RequireSignedTokens = true,
                            ValidateIssuer = true,
                            ValidateAudience = false,
                            ValidateLifetime = false,
                        },
                        ExpectedException = new ExpectedException(typeof(SecurityTokenUnableToValidateException))
                    },
                    new JwtTheoryData
                    {
                        TestId = nameof(Default.AsymmetricJws) + "_" + "ConfigInvalid" + "_" + "IssuerSigningKeyValidationFails" + "_" + "LKGExpired",
                        Token = Default.AsymmetricJws,
                        ValidationParameters = new TokenValidationParameters
                        {
                            ConfigurationManager = new MockConfigurationManager<OpenIdConnectConfiguration>(validConfigKeyValidationFails, validConfig) {LastKnownGoodLifetime = TimeSpan.FromMilliseconds(.1) },
                            ValidateIssuerSigningKey = true,
                            RequireSignedTokens = true,
                            ValidateIssuer = true,
                            ValidateAudience = false,
                            ValidateLifetime = false,
                            IssuerSigningKeyValidatorUsingConfiguration = (securityKey, securityToken, validationParameters, configuration) =>
                            {
                                // mock failing on issuer validation the first time
                                if (configuration == validConfigKeyValidationFails)
                                    return false;
                                else
                                    return true;
                            },
                        },
                        ExpectedException = new ExpectedException(typeof(SecurityTokenInvalidSigningKeyException))
                    },
                    new JwtTheoryData
                    {
                        TestId = nameof(Default.AsymmetricJws) + "_" + "ConfigInvalid" + "_" + "ConfigKeyInvalid" + "_" + "LKGIssuerInvalid" + "_" + "RefreshedConfigValid",
                        Token = Default.AsymmetricJws,
                        ValidationParameters = new TokenValidationParameters
                        {
                            ConfigurationManager = new MockConfigurationManager<OpenIdConnectConfiguration>(incorrectSigningKeysConfig, invalidIssuerConfig, validConfig),
                            ValidateIssuerSigningKey = true,
                            RequireSignedTokens = true,
                            ValidateIssuer = true,
                            ValidateAudience = false,
                            ValidateLifetime = false,
                        }
                    },
                    new JwtTheoryData
                    {
                        TestId = nameof(Default.AsymmetricJws) + "_" + "ConfigInvalid" + "_" + "ConfigKeyInvalid" + "_" + "LKGIssuerInvalid" + "_" + "RefreshedConfigKeyInvalid",
                        Token = Default.AsymmetricJws,
                        ValidationParameters = new TokenValidationParameters
                        {
                            ConfigurationManager = new MockConfigurationManager<OpenIdConnectConfiguration>(incorrectSigningKeysConfig, invalidIssuerConfig, incorrectSigningKeysConfig),
                            ValidateIssuerSigningKey = true,
                            RequireSignedTokens = true,
                            ValidateIssuer = true,
                            ValidateAudience = false,
                            ValidateLifetime = false,
                        },
                        ExpectedException = new ExpectedException(typeof(SecurityTokenSignatureKeyNotFoundException))
                    },
                    new JwtTheoryData
                    {
                        TestId = nameof(Default.AsymmetricJws) + "_" + "ConfigInvalid" + "_" + "ConfigKeyInvalid" + "_" + "LKGFeatureOff",
                        Token = Default.AsymmetricJws,
                        ValidationParameters = new TokenValidationParameters
                        {
                            ConfigurationManager = new MockConfigurationManager<OpenIdConnectConfiguration>(incorrectSigningKeysConfig, validConfig) {UseLastKnownGoodConfiguration = false },
                            ValidateIssuerSigningKey = true,
                            RequireSignedTokens = true,
                            ValidateIssuer = true,
                            ValidateAudience = false,
                            ValidateLifetime = false,
                        },
                        ExpectedException = new ExpectedException(typeof(SecurityTokenSignatureKeyNotFoundException))
                    },
                    new JwtTheoryData
                    {
                        TestId = nameof(Default.AsymmetricJws) + "_" + "ConfigInvalid" + "_" + "ConfigKeyInvalid" + "_" + "LKGFeatureOff" + "_RequestRefreshSucceeds",
                        Token = Default.AsymmetricJws,
                        ValidationParameters = new TokenValidationParameters
                        {
                            ConfigurationManager = new MockConfigurationManager<OpenIdConnectConfiguration>(incorrectSigningKeysConfig, validConfig, validConfig) { UseLastKnownGoodConfiguration = false },
                            ValidateIssuerSigningKey = true,
                            RequireSignedTokens = true,
                            ValidateIssuer = true,
                            ValidateAudience = false,
                            ValidateLifetime = false,
                        },
                    },
                    new JwtTheoryData
                    {
                        TestId = nameof(expiredJws) + "_" + "ConfigKeyInvalid" + "_" + "LKGValid" + "_TokenNotYetValid",
                        Token = expiredJws,
                        ValidationParameters = new TokenValidationParameters
                        {
                            ConfigurationManager = new MockConfigurationManager<OpenIdConnectConfiguration>(incorrectSigningKeysConfig, validConfig, validConfig) { UseLastKnownGoodConfiguration = true },
                            ValidateIssuerSigningKey = true,
                            RequireSignedTokens = true,
                            ValidateIssuer = true,
                            ValidateAudience = false,
                            ValidateLifetime = true,
                        },
                        ExpectedException = new ExpectedException(typeof(SecurityTokenUnableToValidateException))
                    }
                };
            }
        }

        public static TheoryData<JwtTheoryData> ValidateJWEWithLastKnownGoodTheoryData
        {
            get
            {
                var jwe = new JsonWebTokenHandler().CreateToken(Default.PayloadString, Default.SymmetricSigningCredentials, Default.SymmetricEncryptingCredentials);
                var validConfig = new OpenIdConnectConfiguration() { TokenEndpoint = Default.Issuer + "oauth/token", Issuer = Default.Issuer };
                validConfig.SigningKeys.Add(Default.SymmetricSigningKey256);

                // a special IssuerSigningKeyValidator in the tests below is set to fail if this configuration is used in order
                // to mock issuer signing key validation failure
                var validConfigKeyValidationFails = new OpenIdConnectConfiguration() { TokenEndpoint = Default.Issuer + "oauth/token", Issuer = Default.Issuer };
                validConfigKeyValidationFails.SigningKeys.Add(Default.SymmetricSigningKey256);

                var invalidIssuerConfig = new OpenIdConnectConfiguration() { TokenEndpoint = Default.Issuer + "oauth/token", Issuer = Default.Issuer + "2" };
                invalidIssuerConfig.SigningKeys.Add(Default.SymmetricSigningKey256);

                var incorrectSigningKeysConfig = new OpenIdConnectConfiguration() { TokenEndpoint = Default.Issuer + "oauth/token", Issuer = Default.Issuer };
                incorrectSigningKeysConfig.SigningKeys.Add(KeyingMaterial.X509SecurityKey2);

                var incorrectIssuerAndSigningKeysConfig = new OpenIdConnectConfiguration() { TokenEndpoint = Default.Issuer + "oauth/token", Issuer = Default.Issuer + "2" };
                incorrectIssuerAndSigningKeysConfig.SigningKeys.Add(KeyingMaterial.X509SecurityKey2);

                var incorrectSigningKeysConfigWithMatchingKid = new OpenIdConnectConfiguration() { TokenEndpoint = Default.Issuer + "oauth/token", Issuer = Default.Issuer };
                incorrectSigningKeysConfigWithMatchingKid.SigningKeys.Add(new SymmetricSecurityKey(KeyingMaterial.DefaultSymmetricSecurityKey_128.Key) { KeyId = KeyingMaterial.DefaultSymmetricSecurityKey_256.KeyId });

                var notYetValidSecurityTokenDescriptor = Default.X509SecurityTokenDescriptor(Default.SymmetricEncryptingCredentials, Default.X509AsymmetricSigningCredentials, null);
                notYetValidSecurityTokenDescriptor.NotBefore = DateTime.UtcNow + TimeSpan.FromDays(1);
                notYetValidSecurityTokenDescriptor.Expires = DateTime.UtcNow + TimeSpan.FromDays(2);
                var notYetValidJwe = Default.Jwt(notYetValidSecurityTokenDescriptor);
                var notYetValidJweConfig = new OpenIdConnectConfiguration() { TokenEndpoint = Default.Issuer + "oauth/token", Issuer = Default.Issuer };
                notYetValidJweConfig.SigningKeys.Add(Default.X509AsymmetricSigningCredentials.Key);

                return new TheoryData<JwtTheoryData>
                {
                    new JwtTheoryData
                    {
                        TestId = nameof(jwe) + "_" + "ConfigKeyInvalid" + "_" + "LKGValid",
                        Token = jwe,
                        ValidationParameters = new TokenValidationParameters
                        {
                            ConfigurationManager = new MockConfigurationManager<OpenIdConnectConfiguration>(incorrectSigningKeysConfig, validConfig),
                            ValidateIssuerSigningKey = true,
                            RequireSignedTokens = true,
                            ValidateIssuer = true,
                            ValidateAudience = false,
                            ValidateLifetime = false,
                            TokenDecryptionKey = KeyingMaterial.DefaultSymmetricEncryptingCreds_Aes128_Sha2.Key
                        }
                    },
                    new JwtTheoryData
                    {
                        TestId = nameof(jwe) + "_" + "ConfigKeyInvalidKidMatches" + "_" + "LKGValid",
                        Token = jwe,
                        ValidationParameters = new TokenValidationParameters
                        {
                            ConfigurationManager = new MockConfigurationManager<OpenIdConnectConfiguration>(incorrectSigningKeysConfigWithMatchingKid, validConfig),
                            ValidateIssuerSigningKey = true,
                            RequireSignedTokens = true,
                            ValidateIssuer = true,
                            ValidateAudience = false,
                            ValidateLifetime = false,
                            TokenDecryptionKey = KeyingMaterial.DefaultSymmetricEncryptingCreds_Aes128_Sha2.Key                        }
                    },
                    new JwtTheoryData
                    {
                        TestId = nameof(jwe) + "_" + "ConfigKeyInvalidKeyAndIssuer" + "_" + "LKGValid",
                        Token = jwe,
                        ValidationParameters = new TokenValidationParameters
                        {
                            ConfigurationManager = new MockConfigurationManager<OpenIdConnectConfiguration>(incorrectIssuerAndSigningKeysConfig, validConfig),
                            ValidateIssuerSigningKey = true,
                            RequireSignedTokens = true,
                            ValidateIssuer = true,
                            ValidateAudience = false,
                            ValidateLifetime = false,
                            TokenDecryptionKey = KeyingMaterial.DefaultSymmetricEncryptingCreds_Aes128_Sha2.Key
                        }
                    },
                    new JwtTheoryData
                    {
                        TestId = nameof(jwe) + "_" + "ConfigIssuerInvalid" + "_" + "LKGValid",
                        Token = jwe,
                        ValidationParameters = new TokenValidationParameters
                        {
                            ConfigurationManager = new MockConfigurationManager<OpenIdConnectConfiguration>(invalidIssuerConfig, validConfig),
                            ValidateIssuerSigningKey = true,
                            RequireSignedTokens = true,
                            ValidateIssuer = true,
                            ValidateAudience = false,
                            ValidateLifetime = false,
                            TokenDecryptionKey = KeyingMaterial.DefaultSymmetricEncryptingCreds_Aes128_Sha2.Key
                        }
                    },
                    new JwtTheoryData
                    {
                        TestId = nameof(jwe) + "_" + "ConfigIssuerSigningKeyValidationFails" + "_" + "LKGValid",
                        Token = jwe,
                        ValidationParameters = new TokenValidationParameters
                        {
                            ConfigurationManager = new MockConfigurationManager<OpenIdConnectConfiguration>(validConfigKeyValidationFails, validConfig),
                            ValidateIssuerSigningKey = true,
                            RequireSignedTokens = true,
                            ValidateIssuer = true,
                            ValidateAudience = false,
                            ValidateLifetime = false,
                            IssuerSigningKeyValidatorUsingConfiguration = (securityKey, securityToken, validationParameters, configuration) =>
                            {
                                // mock failing on issuer validation the first time
                                if (configuration == validConfigKeyValidationFails)
                                    return false;
                                else
                                    return true;
                            },
                            TokenDecryptionKey = KeyingMaterial.DefaultSymmetricEncryptingCreds_Aes128_Sha2.Key
                        }
                    },
                    new JwtTheoryData
                    {
                        TestId = nameof(jwe) + "_" + "ConfigKeyInvalid" + "_" + "LKGExpired",
                        Token = jwe,
                        ValidationParameters = new TokenValidationParameters
                        {
                            ConfigurationManager = new MockConfigurationManager<OpenIdConnectConfiguration>(incorrectSigningKeysConfig, validConfig) {LastKnownGoodLifetime = TimeSpan.FromMilliseconds(.1) },
                            ValidateIssuerSigningKey = true,
                            RequireSignedTokens = true,
                            ValidateIssuer = true,
                            ValidateAudience = false,
                            ValidateLifetime = false,
                            TokenDecryptionKey = KeyingMaterial.DefaultSymmetricEncryptingCreds_Aes128_Sha2.Key
                        },
                        ExpectedException = new ExpectedException(typeof(SecurityTokenSignatureKeyNotFoundException))
                    },
                    new JwtTheoryData
                    {
                        TestId = nameof(jwe) + "_" + "ConfigIssuerInvalid" + "_" + "LKGExpired",
                        Token = jwe,
                        ValidationParameters = new TokenValidationParameters
                        {
                            ConfigurationManager = new MockConfigurationManager<OpenIdConnectConfiguration>(invalidIssuerConfig, validConfig) {LastKnownGoodLifetime = TimeSpan.FromMilliseconds(.1) },
                            ValidateIssuerSigningKey = true,
                            RequireSignedTokens = true,
                            ValidateIssuer = true,
                            ValidateAudience = false,
                            ValidateLifetime = false,
                            TokenDecryptionKey = KeyingMaterial.DefaultSymmetricEncryptingCreds_Aes128_Sha2.Key
                        },
                        ExpectedException = new ExpectedException(typeof(SecurityTokenInvalidIssuerException))
                    },
                    new JwtTheoryData
                    {
                        TestId = nameof(jwe) + "_" + "ConfigKeyInvalidKidMatches" + "_" + "LKGExpired",
                        Token = jwe,
                        ValidationParameters = new TokenValidationParameters
                        {
                            ConfigurationManager = new MockConfigurationManager<OpenIdConnectConfiguration>(incorrectSigningKeysConfigWithMatchingKid, validConfig) {LastKnownGoodLifetime = TimeSpan.FromMilliseconds(.1) },
                            ValidateIssuerSigningKey = true,
                            RequireSignedTokens = true,
                            ValidateIssuer = true,
                            ValidateAudience = false,
                            ValidateLifetime = false,
                            TokenDecryptionKey = KeyingMaterial.DefaultSymmetricEncryptingCreds_Aes128_Sha2.Key
                        },
                        ExpectedException = new ExpectedException(typeof(SecurityTokenInvalidSignatureException))
                    },
                    new JwtTheoryData
                    {
                        TestId = nameof(jwe) + "_" + "ConfigKeyInvalidKeyAndIssuer" + "_" + "LKGExpired",
                        Token = jwe,
                        ValidationParameters = new TokenValidationParameters
                        {
                            ConfigurationManager = new MockConfigurationManager<OpenIdConnectConfiguration>(incorrectIssuerAndSigningKeysConfig, validConfig) {LastKnownGoodLifetime = TimeSpan.FromMilliseconds(.1) },
                            ValidateIssuerSigningKey = true,
                            RequireSignedTokens = true,
                            ValidateIssuer = true,
                            ValidateAudience = false,
                            ValidateLifetime = false,
                            TokenDecryptionKey = KeyingMaterial.DefaultSymmetricEncryptingCreds_Aes128_Sha2.Key
                        },
                        ExpectedException = new ExpectedException(typeof(SecurityTokenUnableToValidateException))
                    },
                    new JwtTheoryData
                    {
                        TestId = nameof(jwe) + "_" + "ConfigIssuerSigningKeyValidationFails" + "_" + "LKGExpired",
                        Token = jwe,
                        ValidationParameters = new TokenValidationParameters
                        {
                            ConfigurationManager = new MockConfigurationManager<OpenIdConnectConfiguration>(validConfigKeyValidationFails, validConfig) {LastKnownGoodLifetime = TimeSpan.FromMilliseconds(.1) },
                            ValidateIssuerSigningKey = true,
                            RequireSignedTokens = true,
                            ValidateIssuer = true,
                            ValidateAudience = false,
                            ValidateLifetime = false,
                            IssuerSigningKeyValidatorUsingConfiguration = (securityKey, securityToken, validationParameters, configuration) =>
                            {
                                // mock failing on issuer validation the first time
                                if (configuration == validConfigKeyValidationFails)
                                    return false;
                                else
                                    return true;
                            },
                            TokenDecryptionKey = KeyingMaterial.DefaultSymmetricEncryptingCreds_Aes128_Sha2.Key
                        },
                        ExpectedException = new ExpectedException(typeof(SecurityTokenInvalidSigningKeyException))
                    },
                    new JwtTheoryData
                    {
                        TestId = nameof(jwe) + "_" + "ConfigKeyInvalid" + "_" + "LKGIssuerInvalid" + "_" + "RefreshedConfigValid",
                        Token = jwe,
                        ValidationParameters = new TokenValidationParameters
                        {
                            ConfigurationManager = new MockConfigurationManager<OpenIdConnectConfiguration>(incorrectSigningKeysConfig, invalidIssuerConfig, validConfig),
                            ValidateIssuerSigningKey = true,
                            RequireSignedTokens = true,
                            ValidateIssuer = true,
                            ValidateAudience = false,
                            ValidateLifetime = false,
                            TokenDecryptionKey = KeyingMaterial.DefaultSymmetricEncryptingCreds_Aes128_Sha2.Key
                        }
                    },
                    new JwtTheoryData
                    {
                        TestId = nameof(jwe) + "_" + "ConfigKeyInvalid" + "_" + "LKGIssuerInvalid" + "_" + "RefreshedConfigKeyInvalid",
                        Token = jwe,
                        ValidationParameters = new TokenValidationParameters
                        {
                            ConfigurationManager = new MockConfigurationManager<OpenIdConnectConfiguration>(incorrectSigningKeysConfig, invalidIssuerConfig, incorrectSigningKeysConfig),
                            ValidateIssuerSigningKey = true,
                            RequireSignedTokens = true,
                            ValidateIssuer = true,
                            ValidateAudience = false,
                            ValidateLifetime = false,
                            TokenDecryptionKey = KeyingMaterial.DefaultSymmetricEncryptingCreds_Aes128_Sha2.Key
                        },
                        ExpectedException = new ExpectedException(typeof(SecurityTokenSignatureKeyNotFoundException))
                    },
                    new JwtTheoryData
                    {
                        TestId = nameof(jwe) + "_" + "ConfigKeyInvalid" + "_" + "LKGFeatureOff",
                        Token = jwe,
                        ValidationParameters = new TokenValidationParameters
                        {
                            ConfigurationManager = new MockConfigurationManager<OpenIdConnectConfiguration>(incorrectSigningKeysConfig, validConfig) {UseLastKnownGoodConfiguration = false },
                            ValidateIssuerSigningKey = true,
                            RequireSignedTokens = true,
                            ValidateIssuer = true,
                            ValidateAudience = false,
                            ValidateLifetime = false,
                            TokenDecryptionKey = KeyingMaterial.DefaultSymmetricEncryptingCreds_Aes128_Sha2.Key
                        },
                        ExpectedException = new ExpectedException(typeof(SecurityTokenSignatureKeyNotFoundException))
                    },
                    new JwtTheoryData
                    {
                        TestId = nameof(jwe) + "_" + "ConfigKeyInvalid" + "_" + "LKGFeatureOff" + "_RequestRefreshSucceeds",
                        Token = jwe,
                        ValidationParameters = new TokenValidationParameters
                        {
                            ConfigurationManager = new MockConfigurationManager<OpenIdConnectConfiguration>(incorrectSigningKeysConfig, validConfig, validConfig) {UseLastKnownGoodConfiguration = false },
                            ValidateIssuerSigningKey = true,
                            RequireSignedTokens = true,
                            ValidateIssuer = true,
                            ValidateAudience = false,
                            ValidateLifetime = false,
                            TokenDecryptionKey = KeyingMaterial.DefaultSymmetricEncryptingCreds_Aes128_Sha2.Key
                        },
                    },
                    new JwtTheoryData
                    {
                        TestId = nameof(notYetValidJwe) + "_" + "ConfigKeyInvalid" + "_" + "LKGValid" + "_TokenNotYetValid",
                        Token = notYetValidJwe,
                        ValidationParameters = new TokenValidationParameters
                        {
                            ConfigurationManager = new MockConfigurationManager<OpenIdConnectConfiguration>(incorrectSigningKeysConfig, notYetValidJweConfig, notYetValidJweConfig) { UseLastKnownGoodConfiguration = true },
                            ValidateIssuerSigningKey = true,
                            RequireSignedTokens = true,
                            ValidateIssuer = true,
                            ValidateAudience = false,
                            ValidateLifetime = true,
                            TokenDecryptionKey = Default.SymmetricEncryptingCredentials.Key
                        },
                        ExpectedException = new ExpectedException(typeof(SecurityTokenUnableToValidateException))
                    }
                };
            }
        }
    }
}
