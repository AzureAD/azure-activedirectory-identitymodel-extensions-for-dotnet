// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#if NET472_OR_GREATER || NET6_0_OR_GREATER
using Newtonsoft.Json.Linq;
#endif
using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.IdentityModel.TestUtils;
using Microsoft.IdentityModel.Tokens;
using Xunit;

#nullable enable

namespace Microsoft.IdentityModel.JsonWebTokens.Tests
{
    public class JsonWebTokenHandlerValidationParametersTests
    {
        [Theory, MemberData(nameof(JsonWebTokenHandlerValidationParametersTestCases))]
        public async Task ValidateTokenAsync(JsonWebTokenHandlerValidationParametersTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.ValidateTokenAsync", theoryData);

            JsonWebTokenHandler jsonWebTokenHandler = new JsonWebTokenHandler();
            jsonWebTokenHandler.SetDefaultTimesOnTokenCreation = theoryData.SetDefaultValuesOnTokenCreation;

            string jwtString;

            if (theoryData.TokenString != null)
            {
                jwtString = theoryData.TokenString;
            }
            else
            {
                SecurityTokenDescriptor securityTokenDescriptor = new SecurityTokenDescriptor
                {
                    Subject = theoryData.Subject,
                    SigningCredentials = theoryData.SigningCredentials,
                    EncryptingCredentials = theoryData.EncryptingCredentials,
                    AdditionalHeaderClaims = theoryData.AdditionalHeaderParams,
                    Audience = theoryData.Audience,
                    Expires = theoryData.Expires,
                    IssuedAt = theoryData.IssuedAt,
                    Issuer = theoryData.Issuer,
                    NotBefore = theoryData.NotBefore,
                    TokenType = theoryData.TokenType,
                };

                jwtString = jsonWebTokenHandler.CreateToken(securityTokenDescriptor);
            }

            TokenValidationResult tokenValidationParametersResult =
                await jsonWebTokenHandler.ValidateTokenAsync(jwtString, theoryData.TokenValidationParameters);
            ValidationResult<ValidatedToken> validationParametersResult =
                await jsonWebTokenHandler.ValidateTokenAsync(
                    jwtString, theoryData.ValidationParameters!, theoryData.CallContext, CancellationToken.None);

            if (tokenValidationParametersResult.IsValid != theoryData.ExpectedIsValid)
                context.AddDiff($"tokenValidationParametersResult.IsValid != theoryData.ExpectedIsValid");

            if (validationParametersResult.IsSuccess != theoryData.ExpectedIsValid)
                context.AddDiff($"validationParametersResult.IsSuccess != theoryData.ExpectedIsValid");

            if (theoryData.ExpectedIsValid &&
                tokenValidationParametersResult.IsValid &&
                validationParametersResult.IsSuccess)
            {
                IdentityComparer.AreEqual(
                    tokenValidationParametersResult.ClaimsIdentity,
                    validationParametersResult.UnwrapResult().ClaimsIdentity,
                    context);
                IdentityComparer.AreEqual(
                    tokenValidationParametersResult.Claims,
                    validationParametersResult.UnwrapResult().Claims,
                    context);
            }
            else
            {
                theoryData.ExpectedException.ProcessException(tokenValidationParametersResult.Exception, context);

                if (!validationParametersResult.IsSuccess)
                {
                    // If there is a special case for the ValidationParameters path, use that.
                    if (theoryData.ExpectedExceptionValidationParameters != null)
                        theoryData.ExpectedExceptionValidationParameters
                            .ProcessException(validationParametersResult.UnwrapError().GetException(), context);
                    else
                        theoryData.ExpectedException
                            .ProcessException(validationParametersResult.UnwrapError().GetException(), context);
                }
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<JsonWebTokenHandlerValidationParametersTheoryData> JsonWebTokenHandlerValidationParametersTestCases
        {
            get
            {
                return new TheoryData<JsonWebTokenHandlerValidationParametersTheoryData>
                {
                    new JsonWebTokenHandlerValidationParametersTheoryData("Valid")
                    {
                        TokenValidationParameters = CreateTokenValidationParameters(
                            Default.Issuer, [Default.Audience], Default.AsymmetricSigningKey),
                        ValidationParameters = CreateValidationParameters(
                            Default.Issuer, [Default.Audience], Default.AsymmetricSigningKey),
                    },
                    new JsonWebTokenHandlerValidationParametersTheoryData("Invalid_ValidationParametersNull")
                    {
                        ExpectedIsValid = false,
                        ExpectedException = ExpectedException.ArgumentNullException("IDX10000:"),
                    },
                    new JsonWebTokenHandlerValidationParametersTheoryData("Invalid_MalformedToken")
                    {
                        TokenString = "malformedToken",
                        TokenValidationParameters = CreateTokenValidationParameters(
                            Default.Issuer, [Default.Audience], Default.AsymmetricSigningKey),
                        ValidationParameters = CreateValidationParameters(
                            Default.Issuer, [Default.Audience], Default.AsymmetricSigningKey),
                        ExpectedIsValid = false,
                        ExpectedException = ExpectedException.SecurityTokenMalformedException("IDX14100:"),
                        ExpectedExceptionValidationParameters = ExpectedException.SecurityTokenMalformedException("IDX14107:", typeof(SecurityTokenMalformedException)),
                    },
                    new JsonWebTokenHandlerValidationParametersTheoryData("Invalid_Issuer")
                    {
                        TokenValidationParameters = CreateTokenValidationParameters(
                            Default.Issuer, [Default.Audience], Default.AsymmetricSigningKey),
                        ValidationParameters = CreateValidationParameters(
                            Default.Issuer, [Default.Audience], Default.AsymmetricSigningKey),
                        Issuer = "InvalidIssuer",
                        ExpectedIsValid = false,
                        ExpectedException = ExpectedException.SecurityTokenInvalidIssuerException("IDX10205:"),
                        // ValidateTokenAsync with ValidationParameters returns a different error message to account for the
                        // removal of the ValidIssuer property from the ValidationParameters class.
                        ExpectedExceptionValidationParameters = ExpectedException.SecurityTokenInvalidIssuerException("IDX10212:"),
                    },
                    new JsonWebTokenHandlerValidationParametersTheoryData("Invalid_Audience")
                    {
                        TokenValidationParameters = CreateTokenValidationParameters(
                            Default.Issuer, [Default.Audience], Default.AsymmetricSigningKey),
                        ValidationParameters = CreateValidationParameters(
                            Default.Issuer, [Default.Audience], Default.AsymmetricSigningKey),
                        Audience = "InvalidAudience",
                        ExpectedIsValid = false,
                        ExpectedException = ExpectedException.SecurityTokenInvalidAudienceException("IDX10214:"),
                        // ValidateTokenAsync with ValidationParameters returns a different error message to account for the
                        // removal of the ValidAudience property from the ValidationParameters class.
                        ExpectedExceptionValidationParameters = ExpectedException.SecurityTokenInvalidAudienceException("IDX10215:"),
                    },
                    new JsonWebTokenHandlerValidationParametersTheoryData("Valid_WithinFiveMinutesOfExpiration")
                    {
                        // Token expired 4 minutes ago, but the clock skew is 5 minutes.
                        TokenValidationParameters = CreateTokenValidationParameters(
                            Default.Issuer, [Default.Audience], Default.AsymmetricSigningKey),
                        ValidationParameters = CreateValidationParameters(
                            Default.Issuer, [Default.Audience], Default.AsymmetricSigningKey),
                        IssuedAt = DateTime.UtcNow - TimeSpan.FromHours(2),
                        NotBefore = DateTime.UtcNow - TimeSpan.FromHours(2),
                        Expires = DateTime.UtcNow - TimeSpan.FromMinutes(4),
                    },
                    new JsonWebTokenHandlerValidationParametersTheoryData("Valid_WithinFiveMinutesOfNotBefore")
                    {
                        // Token is not yet valid for another 4 minutes, but the clock skew is 5 minutes.
                        TokenValidationParameters = CreateTokenValidationParameters(
                            Default.Issuer, [Default.Audience], Default.AsymmetricSigningKey),
                        ValidationParameters = CreateValidationParameters(
                            Default.Issuer, [Default.Audience], Default.AsymmetricSigningKey),
                        IssuedAt = DateTime.UtcNow,
                        NotBefore = DateTime.UtcNow + TimeSpan.FromMinutes(4),
                        Expires = DateTime.UtcNow + TimeSpan.FromHours(2),
                    },
                    new JsonWebTokenHandlerValidationParametersTheoryData("Invalid_Expired")
                    {
                        TokenValidationParameters = CreateTokenValidationParameters(
                            Default.Issuer, [Default.Audience], Default.AsymmetricSigningKey),
                        ValidationParameters = CreateValidationParameters(
                            Default.Issuer, [Default.Audience], Default.AsymmetricSigningKey),
                        IssuedAt = DateTime.UtcNow - TimeSpan.FromDays(2),
                        NotBefore = DateTime.UtcNow - TimeSpan.FromDays(2),
                        Expires = DateTime.UtcNow - TimeSpan.FromDays(1),
                        ExpectedIsValid = false,
                        ExpectedException = ExpectedException.SecurityTokenExpiredException("IDX10223:"),
                    },
                    new JsonWebTokenHandlerValidationParametersTheoryData("Invalid_NotYetValid")
                    {
                        TokenValidationParameters = CreateTokenValidationParameters(
                            Default.Issuer, [Default.Audience], Default.AsymmetricSigningKey),
                        ValidationParameters = CreateValidationParameters(
                            Default.Issuer, [Default.Audience], Default.AsymmetricSigningKey),
                        IssuedAt = DateTime.UtcNow + TimeSpan.FromDays(1),
                        NotBefore = DateTime.UtcNow + TimeSpan.FromDays(1),
                        Expires = DateTime.UtcNow + TimeSpan.FromDays(2),
                        ExpectedIsValid = false,
                        ExpectedException = ExpectedException.SecurityTokenNotYetValidException("IDX10222:"),
                    },
                    new JsonWebTokenHandlerValidationParametersTheoryData("Invalid_NoExpiration")
                    {
                        TokenValidationParameters = CreateTokenValidationParameters(
                            Default.Issuer, [Default.Audience], Default.AsymmetricSigningKey),
                        ValidationParameters = CreateValidationParameters(
                            Default.Issuer, [Default.Audience], Default.AsymmetricSigningKey),
                        Expires = null,
                        NotBefore = DateTime.UtcNow,
                        IssuedAt = DateTime.UtcNow,
                        ExpectedIsValid = false,
                        SetDefaultValuesOnTokenCreation = false,
                        ExpectedException = ExpectedException.SecurityTokenNoExpirationException("IDX10225:"),
                    },
                    new JsonWebTokenHandlerValidationParametersTheoryData("Invalid_InvalidLifetime")
                                        {
                        TokenValidationParameters = CreateTokenValidationParameters(
                            Default.Issuer, [Default.Audience], Default.AsymmetricSigningKey),
                        ValidationParameters = CreateValidationParameters(
                            Default.Issuer, [Default.Audience], Default.AsymmetricSigningKey),
                        IssuedAt = DateTime.UtcNow + TimeSpan.FromDays(2),
                        NotBefore = DateTime.UtcNow + TimeSpan.FromDays(2),
                        Expires = DateTime.UtcNow + TimeSpan.FromDays(1),
                        ExpectedIsValid = false,
                        ExpectedException = ExpectedException.SecurityTokenInvalidLifetimeException("IDX10224:"),
                    },
                    new JsonWebTokenHandlerValidationParametersTheoryData("Invalid_TokenTypeNotSupported")
                    {
                        // Token Type is 'JWT' but only 'none' is considered valid for this test's purposes
                        TokenValidationParameters = CreateTokenValidationParameters(
                            Default.Issuer, [Default.Audience], Default.AsymmetricSigningKey,
                            validTokenTypes: ["none"]),
                        ValidationParameters = CreateValidationParameters(
                            Default.Issuer, [Default.Audience], Default.AsymmetricSigningKey,
                            validTokenTypes: ["none"]),
                        ExpectedIsValid = false,
                        ExpectedException = ExpectedException.SecurityTokenInvalidTypeException("IDX10257:"),
                    },
                    new JsonWebTokenHandlerValidationParametersTheoryData("Invalid_TokenReplayDetected_TokenFoundInCache")
                    {
                        TokenValidationParameters = CreateTokenValidationParameters(
                            Default.Issuer, [Default.Audience], Default.AsymmetricSigningKey,
                            tokenReplayCache: new TestTokenReplayCache(false, true)),
                        ValidationParameters = CreateValidationParameters(
                            Default.Issuer, [Default.Audience], Default.AsymmetricSigningKey,
                            tokenReplayCache: new TestTokenReplayCache(false, true)),
                        ExpectedIsValid = false,
                        ExpectedException = ExpectedException.SecurityTokenReplayDetectedException("IDX10228:"),
                    },
                    new JsonWebTokenHandlerValidationParametersTheoryData("Invalid_TokenReplayDetected_AddToCacheFailed")
                    {
                        TokenValidationParameters = CreateTokenValidationParameters(
                            Default.Issuer, [Default.Audience], Default.AsymmetricSigningKey,
                            tokenReplayCache: new TestTokenReplayCache(false, false)),
                        ValidationParameters = CreateValidationParameters(
                            Default.Issuer, [Default.Audience], Default.AsymmetricSigningKey,
                            tokenReplayCache: new TestTokenReplayCache(false, false)),
                        ExpectedIsValid = false,
                        ExpectedException = ExpectedException.SecurityTokenReplayAddFailedException("IDX10229:"),
                    },
                    new JsonWebTokenHandlerValidationParametersTheoryData("Invalid_TokenNotSigned")
                    {
                        TokenValidationParameters = CreateTokenValidationParameters(
                            Default.Issuer, [Default.Audience], Default.AsymmetricSigningKey),
                        ValidationParameters = CreateValidationParameters(
                            Default.Issuer, [Default.Audience], Default.AsymmetricSigningKey),
                        SigningCredentials = null,
                        ExpectedIsValid = false,
                        ExpectedException = ExpectedException.SecurityTokenInvalidSignatureException("IDX10504:"),
                    },
                    new JsonWebTokenHandlerValidationParametersTheoryData("Invalid_TokenSignedWithDifferentKey_KeyIdPresent_TryAllKeysFalse")
                    {
                        TokenValidationParameters = CreateTokenValidationParameters(
                            Default.Issuer, [Default.Audience], Default.AsymmetricSigningKey),
                        ValidationParameters = CreateValidationParameters(
                            Default.Issuer, [Default.Audience], Default.AsymmetricSigningKey),
                        SigningCredentials = Default.SymmetricSigningCredentials,
                        ExpectedIsValid = false,
                        ExpectedException = ExpectedException.SecurityTokenSignatureKeyNotFoundException("IDX10500:"),
                        // ValidateTokenAsync with ValidationParameters returns a different error message in the case where a
                        // key is not found in the IssuerSigningKeys collection and TryAllKeys is false.
                        ExpectedExceptionValidationParameters = ExpectedException.SecurityTokenSignatureKeyNotFoundException("IDX10502:"),
                    },
                    new JsonWebTokenHandlerValidationParametersTheoryData("Invalid_TokenSignedWithDifferentKey_KeyIdPresent_TryAllKeysTrue")
                    {
                        TokenValidationParameters = CreateTokenValidationParameters(
                            Default.Issuer, [Default.Audience], Default.AsymmetricSigningKey, tryAllKeys: true),
                        ValidationParameters = CreateValidationParameters(
                            Default.Issuer, [Default.Audience], Default.AsymmetricSigningKey, tryAllKeys: true),
                        SigningCredentials = Default.SymmetricSigningCredentials,
                        ExpectedIsValid = false,
                        ExpectedException = ExpectedException.SecurityTokenSignatureKeyNotFoundException("IDX10503:"),
                    },
                    new JsonWebTokenHandlerValidationParametersTheoryData("Invalid_TokenSignedWithDifferentKey_KeyIdNotPresent_TryAllKeysFalse")
                    {
                        TokenValidationParameters = CreateTokenValidationParameters(
                            Default.Issuer, [Default.Audience], Default.AsymmetricSigningKey),
                        ValidationParameters = CreateValidationParameters(
                            Default.Issuer, [Default.Audience], Default.AsymmetricSigningKey),
                        SigningCredentials = KeyingMaterial.DefaultSymmetricSigningCreds_256_Sha2_NoKeyId,
                        ExpectedIsValid = false,
                        ExpectedException = ExpectedException.SecurityTokenSignatureKeyNotFoundException("IDX10500:"),
                    },
                    new JsonWebTokenHandlerValidationParametersTheoryData("Invalid_TokenSignedWithDifferentKey_KeyIdNotPresent_TryAllKeysTrue")
                    {
                        TokenValidationParameters = CreateTokenValidationParameters(
                            Default.Issuer, [Default.Audience], Default.AsymmetricSigningKey, tryAllKeys: true),
                        ValidationParameters = CreateValidationParameters(
                            Default.Issuer, [Default.Audience], Default.AsymmetricSigningKey, tryAllKeys: true),
                        SigningCredentials = KeyingMaterial.DefaultSymmetricSigningCreds_256_Sha2_NoKeyId,
                        ExpectedIsValid = false,
                        ExpectedException = ExpectedException.SecurityTokenSignatureKeyNotFoundException("IDX10517:"),
                    },
                    new JsonWebTokenHandlerValidationParametersTheoryData("Invalid_TokenSignedWithInvalidAlgorithm")
                    {
                        // Token is signed with HmacSha256 but only sha256 is considered valid for this test's purposes
                        TokenValidationParameters = CreateTokenValidationParameters(
                            Default.Issuer, [Default.Audience], KeyingMaterial.DefaultSymmetricSigningCreds_256_Sha2.Key,
                            validAlgorithms: [SecurityAlgorithms.Sha256]),
                        ValidationParameters = CreateValidationParameters(
                            Default.Issuer, [Default.Audience], KeyingMaterial.DefaultSymmetricSigningCreds_256_Sha2.Key,
                            validAlgorithms: [SecurityAlgorithms.Sha256]),
                        SigningCredentials = KeyingMaterial.DefaultSymmetricSigningCreds_256_Sha2,
                        ExpectedIsValid = false,
                        ExpectedException = ExpectedException.SecurityTokenInvalidSignatureException("IDX10511:"),
                        ExpectedExceptionValidationParameters = ExpectedException.SecurityTokenInvalidSignatureException(
                            "IDX10518:",
                            innerTypeExpected: typeof(SecurityTokenInvalidAlgorithmException))
                    },
                    new JsonWebTokenHandlerValidationParametersTheoryData("Valid_JWE")
                    {
                        EncryptingCredentials = new EncryptingCredentials(
                            KeyingMaterial.DefaultX509Key_2048,
                            SecurityAlgorithms.RsaPKCS1,
                            SecurityAlgorithms.Aes128CbcHmacSha256),
                        SigningCredentials = KeyingMaterial.DefaultSymmetricSigningCreds_256_Sha2,
                        TokenValidationParameters = CreateTokenValidationParameters(
                            Default.Issuer, [Default.Audience], KeyingMaterial.DefaultSymmetricSigningCreds_256_Sha2.Key,
                            tokenDecryptionKey: KeyingMaterial.DefaultX509Key_2048),
                        ValidationParameters = CreateValidationParameters(
                            Default.Issuer, [Default.Audience], KeyingMaterial.DefaultSymmetricSigningCreds_256_Sha2.Key,
                            tokenDecryptionKey: KeyingMaterial.DefaultX509Key_2048),
                    },
#if NET472 || NET6_0_OR_GREATER
                    new JsonWebTokenHandlerValidationParametersTheoryData("Valid_JWE_EcdhEs")
                    {
                        EncryptingCredentials = new EncryptingCredentials(
                                    new ECDsaSecurityKey(KeyingMaterial.JsonWebKeyP521, true),
                                    SecurityAlgorithms.EcdhEsA256kw,
                                    SecurityAlgorithms.Aes128CbcHmacSha256)
                        {
                            KeyExchangePublicKey = KeyingMaterial.JsonWebKeyP521_Public
                        },
                        SigningCredentials = KeyingMaterial.DefaultSymmetricSigningCreds_256_Sha2,
                        AdditionalHeaderParams = AdditionalEcdhEsHeaderParameters(KeyingMaterial.JsonWebKeyP521_Public),
                        TokenValidationParameters = CreateTokenValidationParameters(
                            Default.Issuer, [Default.Audience], KeyingMaterial.DefaultSymmetricSigningCreds_256_Sha2.Key,
                            tokenDecryptionKey: new ECDsaSecurityKey(KeyingMaterial.JsonWebKeyP521, true)),
                        ValidationParameters = CreateValidationParameters(
                            Default.Issuer, [Default.Audience], KeyingMaterial.DefaultSymmetricSigningCreds_256_Sha2.Key,
                            tokenDecryptionKey: new ECDsaSecurityKey(KeyingMaterial.JsonWebKeyP521, true)),
                    },
#endif
                    new JsonWebTokenHandlerValidationParametersTheoryData("Invalid_JWE_NoDecryptionKeys")
                    {
                        EncryptingCredentials = new EncryptingCredentials(
                            KeyingMaterial.DefaultX509Key_2048,
                            SecurityAlgorithms.RsaPKCS1,
                            SecurityAlgorithms.Aes128CbcHmacSha256),
                        SigningCredentials = KeyingMaterial.DefaultSymmetricSigningCreds_256_Sha2,
                        TokenValidationParameters = CreateTokenValidationParameters(
                            Default.Issuer, [Default.Audience], KeyingMaterial.DefaultSymmetricSigningCreds_256_Sha2.Key),
                        ValidationParameters = CreateValidationParameters(
                            Default.Issuer, [Default.Audience], KeyingMaterial.DefaultSymmetricSigningCreds_256_Sha2.Key),
                        ExpectedIsValid = false,
                        ExpectedException = ExpectedException.SecurityTokenDecryptionFailedException("IDX10609:"),
                    },
                    new JsonWebTokenHandlerValidationParametersTheoryData("Invalid_JWE_WrongDecryptionKey")
                    {
                        EncryptingCredentials = new EncryptingCredentials(
                            KeyingMaterial.DefaultX509Key_2048,
                            SecurityAlgorithms.RsaPKCS1,
                            SecurityAlgorithms.Aes128CbcHmacSha256),
                        SigningCredentials = KeyingMaterial.DefaultSymmetricSigningCreds_256_Sha2,
                        TokenValidationParameters = CreateTokenValidationParameters(
                            Default.Issuer, [Default.Audience], KeyingMaterial.DefaultSymmetricSigningCreds_256_Sha2.Key,
                            tokenDecryptionKey: KeyingMaterial.DefaultRsaSecurityKey1),
                        ValidationParameters = CreateValidationParameters(
                            Default.Issuer, [Default.Audience], KeyingMaterial.DefaultSymmetricSigningCreds_256_Sha2.Key,
                            tokenDecryptionKey: KeyingMaterial.DefaultRsaSecurityKey1),
                        ExpectedIsValid = false,
                        ExpectedException = ExpectedException.SecurityTokenKeyWrapException("IDX10618:"),
                    },
                    new JsonWebTokenHandlerValidationParametersTheoryData("Invalid_JWE_WrongDecryptionKey")
                    {
                        EncryptingCredentials = new EncryptingCredentials(
                            KeyingMaterial.DefaultX509Key_2048,
                            SecurityAlgorithms.RsaPKCS1,
                            SecurityAlgorithms.Aes128CbcHmacSha256),
                        SigningCredentials = KeyingMaterial.DefaultSymmetricSigningCreds_256_Sha2,
                        TokenValidationParameters = CreateTokenValidationParameters(
                            Default.Issuer, [Default.Audience], KeyingMaterial.DefaultSymmetricSigningCreds_256_Sha2.Key,
                            tokenDecryptionKey: KeyingMaterial.DefaultRsaSecurityKey1),
                        ValidationParameters = CreateValidationParameters(
                            Default.Issuer, [Default.Audience], KeyingMaterial.DefaultSymmetricSigningCreds_256_Sha2.Key,
                            tokenDecryptionKey: KeyingMaterial.DefaultRsaSecurityKey1),
                        ExpectedIsValid = false,
                        ExpectedException = ExpectedException.SecurityTokenKeyWrapException("IDX10618:"),
                    },
                };

                static TokenValidationParameters CreateTokenValidationParameters(
                    string? issuer,
                    List<string>? audiences,
                    SecurityKey? issuerSigningKey,
                    SecurityKey? tokenDecryptionKey = null,
                    List<string>? validAlgorithms = null,
                    List<string>? validTokenTypes = null,
                    ITokenReplayCache? tokenReplayCache = null,
                    bool tryAllKeys = false) => new TokenValidationParameters
                    {
                        ValidAlgorithms = validAlgorithms,
                        ValidateAudience = true,
                        ValidateIssuer = true,
                        ValidateLifetime = true,
                        ValidateTokenReplay = true,
                        ValidateIssuerSigningKey = true,
                        IssuerSigningKey = issuerSigningKey,
                        TokenDecryptionKey = tokenDecryptionKey,
                        ValidAudiences = audiences,
                        ValidIssuer = issuer,
                        TryAllIssuerSigningKeys = tryAllKeys,
                        ValidTypes = validTokenTypes,
                        TokenReplayCache = tokenReplayCache,
                    };

                static ValidationParameters CreateValidationParameters(
                    string? issuer,
                    List<string>? audiences,
                    SecurityKey? issuerSigningKey,
                    SecurityKey? tokenDecryptionKey = null,
                    List<string>? validAlgorithms = null,
                    List<string>? validTokenTypes = null,
                    ITokenReplayCache? tokenReplayCache = null,
                    bool tryAllKeys = false)
                {
                    ValidationParameters validationParameters = new ValidationParameters();
                    validationParameters.ValidIssuers.Add(issuer);
                    audiences?.ForEach(audience => validationParameters.ValidAudiences.Add(audience));
                    validTokenTypes?.ForEach(tokenType => validationParameters.ValidTypes.Add(tokenType));
                    validationParameters.IssuerSigningKeys.Add(issuerSigningKey);
                    validationParameters.TryAllIssuerSigningKeys = tryAllKeys;
                    validationParameters.TokenReplayCache = tokenReplayCache;
                    if (validAlgorithms is not null)
                        validationParameters.ValidAlgorithms = validAlgorithms;
                    if (tokenDecryptionKey is not null)
                        validationParameters.TokenDecryptionKeys = [tokenDecryptionKey];

                    return validationParameters;
                }

#if NET472 || NET6_0_OR_GREATER
                static Dictionary<string, object> AdditionalEcdhEsHeaderParameters(JsonWebKey publicKeySender)
                {
                    var epkJObject = new JObject();
                    epkJObject.Add(JsonWebKeyParameterNames.Kty, publicKeySender.Kty);
                    epkJObject.Add(JsonWebKeyParameterNames.Crv, publicKeySender.Crv);
                    epkJObject.Add(JsonWebKeyParameterNames.X, publicKeySender.X);
                    epkJObject.Add(JsonWebKeyParameterNames.Y, publicKeySender.Y);

                    Dictionary<string, object> additionalHeaderParams = new Dictionary<string, object>()
                    {
                        { JsonWebTokens.JwtHeaderParameterNames.Apu, Guid.NewGuid().ToString() },
                        { JsonWebTokens.JwtHeaderParameterNames.Apv, Guid.NewGuid().ToString() },
                        { JsonWebTokens.JwtHeaderParameterNames.Epk, epkJObject.ToString(Newtonsoft.Json.Formatting.None) }
                    };

                    return additionalHeaderParams;
                }
#endif
            }
        }

        private class TestTokenReplayCache : ITokenReplayCache
        {
            private bool _onAddReturnValue;
            private bool _onFindReturnValue;
            public TestTokenReplayCache(bool onAddReturnValue, bool onFindReturnValue)
            {
                _onAddReturnValue = onAddReturnValue;
                _onFindReturnValue = onFindReturnValue;
            }
            public bool TryAdd(string securityToken, DateTime expirationTime)
            {
                return _onAddReturnValue;
            }

            public bool TryFind(string securityToken)
            {
                return _onFindReturnValue;
            }
        }

        public class JsonWebTokenHandlerValidationParametersTheoryData : TheoryDataBase
        {
            public JsonWebTokenHandlerValidationParametersTheoryData(string testId) : base(testId) { }
            public string? TokenString { get; internal set; } = null;
            public bool SetDefaultValuesOnTokenCreation { get; internal set; } = true;
            public SigningCredentials? SigningCredentials { get; internal set; } = Default.AsymmetricSigningCredentials;
            public EncryptingCredentials? EncryptingCredentials { get; internal set; }
            public IDictionary<string, object>? AdditionalHeaderParams { get; internal set; }
            public ClaimsIdentity? Subject { get; internal set; } = Default.ClaimsIdentity;
            public string Audience { get; internal set; } = Default.Audience;
            public string Issuer { get; internal set; } = Default.Issuer;
            public DateTime? IssuedAt { get; internal set; }
            public DateTime? NotBefore { get; internal set; }
            public DateTime? Expires { get; internal set; }
            internal bool ExpectedIsValid { get; set; } = true;
            public string? TokenType { get; internal set; }
            internal TokenValidationParameters? TokenValidationParameters { get; set; }
            internal ValidationParameters? ValidationParameters { get; set; }

            // only set if we expect a different message on this path
            internal ExpectedException? ExpectedExceptionValidationParameters { get; set; } = null;
        }
    }
}
#nullable restore
