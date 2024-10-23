// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#if NET472_OR_GREATER || NET6_0_OR_GREATER
using System;
using Newtonsoft.Json.Linq;
#endif
using System.Collections.Generic;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.IdentityModel.TestUtils;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace Microsoft.IdentityModel.JsonWebTokens.Tests
{
    public class JsonWebTokenHandlerValidationParametersTests
    {
        [Theory, MemberData(nameof(JsonWebTokenHandlerValidationParametersTestCases), DisableDiscoveryEnumeration = true)]
        public async Task ValidateTokenAsync(JsonWebTokenHandlerValidationParametersTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.ValidateTokenAsync", theoryData);

            JsonWebTokenHandler jsonWebTokenHandler = new JsonWebTokenHandler();

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
                    Audience = Default.Audience,
                    Issuer = theoryData.Issuer,
                };

                jwtString = jsonWebTokenHandler.CreateToken(securityTokenDescriptor);
            }

            TokenValidationResult tokenValidationParametersResult =
                await jsonWebTokenHandler.ValidateTokenAsync(jwtString, theoryData.TokenValidationParameters);

            ValidationResult<ValidatedToken> validationParametersResult =
                await jsonWebTokenHandler.ValidateTokenAsync(
                    jwtString, theoryData.ValidationParameters, theoryData.CallContext, CancellationToken.None);

            if (tokenValidationParametersResult.IsValid != theoryData.ExpectedIsValid)
                context.AddDiff($"tokenValidationParametersResult.IsValid != theoryData.ExpectedIsValid");

            if (validationParametersResult.IsValid != theoryData.ExpectedIsValid)
                context.AddDiff($"validationParametersResult.IsSuccess != theoryData.ExpectedIsValid");

            if (theoryData.ExpectedIsValid &&
                tokenValidationParametersResult.IsValid &&
                validationParametersResult.IsValid)
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

                if (!validationParametersResult.IsValid)
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
                            Default.Issuer, Default.AsymmetricSigningKey),
                        ValidationParameters = CreateValidationParameters(
                            Default.Issuer, Default.AsymmetricSigningKey),
                    },
                    new JsonWebTokenHandlerValidationParametersTheoryData("Invalid_MalformedToken")
                    {
                        TokenString = "malformedToken",
                        TokenValidationParameters = CreateTokenValidationParameters(
                            Default.Issuer, Default.AsymmetricSigningKey),
                        ValidationParameters = CreateValidationParameters(
                            Default.Issuer, Default.AsymmetricSigningKey),
                        ExpectedIsValid = false,
                        ExpectedException = ExpectedException.SecurityTokenMalformedException("IDX14100:"),
                        ExpectedExceptionValidationParameters = ExpectedException.SecurityTokenMalformedException("IDX14107:", typeof(SecurityTokenMalformedException)),
                    },
                    new JsonWebTokenHandlerValidationParametersTheoryData("Invalid_TokenSignedWithInvalidAlgorithm")
                    {
                        // Token is signed with HmacSha256 but only sha256 is considered valid for this test's purposes
                        TokenValidationParameters = CreateTokenValidationParameters(
                            Default.Issuer, KeyingMaterial.DefaultSymmetricSigningCreds_256_Sha2.Key,
                            validAlgorithms: [SecurityAlgorithms.Sha256]),
                        ValidationParameters = CreateValidationParameters(
                            Default.Issuer, KeyingMaterial.DefaultSymmetricSigningCreds_256_Sha2.Key,
                            validAlgorithms: [SecurityAlgorithms.Sha256]),
                        SigningCredentials = KeyingMaterial.DefaultSymmetricSigningCreds_256_Sha2,
                        ExpectedIsValid = false,
                        ExpectedException = ExpectedException.SecurityTokenInvalidSignatureException("IDX10511:"),
                        ExpectedExceptionValidationParameters = ExpectedException.SecurityTokenInvalidAlgorithmException("IDX10518:")
                    },
                    new JsonWebTokenHandlerValidationParametersTheoryData("Valid_JWE")
                    {
                        EncryptingCredentials = new EncryptingCredentials(
                            KeyingMaterial.DefaultX509Key_2048,
                            SecurityAlgorithms.RsaPKCS1,
                            SecurityAlgorithms.Aes128CbcHmacSha256),
                        SigningCredentials = KeyingMaterial.DefaultSymmetricSigningCreds_256_Sha2,
                        TokenValidationParameters = CreateTokenValidationParameters(
                            Default.Issuer, KeyingMaterial.DefaultSymmetricSigningCreds_256_Sha2.Key,
                            tokenDecryptionKey: KeyingMaterial.DefaultX509Key_2048),
                        ValidationParameters = CreateValidationParameters(
                            Default.Issuer, KeyingMaterial.DefaultSymmetricSigningCreds_256_Sha2.Key,
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
                            Default.Issuer, KeyingMaterial.DefaultSymmetricSigningCreds_256_Sha2.Key,
                            tokenDecryptionKey: new ECDsaSecurityKey(KeyingMaterial.JsonWebKeyP521, true)),
                        ValidationParameters = CreateValidationParameters(
                            Default.Issuer, KeyingMaterial.DefaultSymmetricSigningCreds_256_Sha2.Key,
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
                            Default.Issuer, KeyingMaterial.DefaultSymmetricSigningCreds_256_Sha2.Key),
                        ValidationParameters = CreateValidationParameters(
                            Default.Issuer, KeyingMaterial.DefaultSymmetricSigningCreds_256_Sha2.Key),
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
                            Default.Issuer, KeyingMaterial.DefaultSymmetricSigningCreds_256_Sha2.Key,
                            tokenDecryptionKey: KeyingMaterial.DefaultRsaSecurityKey1),
                        ValidationParameters = CreateValidationParameters(
                            Default.Issuer, KeyingMaterial.DefaultSymmetricSigningCreds_256_Sha2.Key,
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
                            Default.Issuer, KeyingMaterial.DefaultSymmetricSigningCreds_256_Sha2.Key,
                            tokenDecryptionKey: KeyingMaterial.DefaultRsaSecurityKey1),
                        ValidationParameters = CreateValidationParameters(
                            Default.Issuer, KeyingMaterial.DefaultSymmetricSigningCreds_256_Sha2.Key,
                            tokenDecryptionKey: KeyingMaterial.DefaultRsaSecurityKey1),
                        ExpectedIsValid = false,
                        ExpectedException = ExpectedException.SecurityTokenKeyWrapException("IDX10618:"),
                    },
                };

                static TokenValidationParameters CreateTokenValidationParameters(
                    string issuer,
                    SecurityKey issuerSigningKey,
                    SecurityKey tokenDecryptionKey = null,
                    List<string> validAlgorithms = null,
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
                        ValidAudiences = [Default.Audience],
                        ValidIssuer = issuer,
                        TryAllIssuerSigningKeys = tryAllKeys,
                    };

                static ValidationParameters CreateValidationParameters(
                    string issuer,
                    SecurityKey issuerSigningKey,
                    SecurityKey tokenDecryptionKey = null,
                    List<string> validAlgorithms = null,
                    bool tryAllKeys = false)
                {
                    ValidationParameters validationParameters = new ValidationParameters();
                    validationParameters.ValidAudiences.Add(Default.Audience);
                    validationParameters.ValidIssuers.Add(issuer);
                    validationParameters.IssuerSigningKeys.Add(issuerSigningKey);
                    validationParameters.TryAllIssuerSigningKeys = tryAllKeys;
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

        public class JsonWebTokenHandlerValidationParametersTheoryData : TheoryDataBase
        {
            public JsonWebTokenHandlerValidationParametersTheoryData(string testId) : base(testId) { }
            public string TokenString { get; internal set; } = null;
            public SigningCredentials SigningCredentials { get; internal set; } = Default.AsymmetricSigningCredentials;
            public EncryptingCredentials EncryptingCredentials { get; internal set; }
            public IDictionary<string, object> AdditionalHeaderParams { get; internal set; }
            public ClaimsIdentity Subject { get; internal set; } = Default.ClaimsIdentity;
            public string Issuer { get; internal set; } = Default.Issuer;
            internal bool ExpectedIsValid { get; set; } = true;
            internal TokenValidationParameters TokenValidationParameters { get; set; }
            internal ValidationParameters ValidationParameters { get; set; }

            // only set if we expect a different message on this path
            internal ExpectedException ExpectedExceptionValidationParameters { get; set; } = null;
        }
    }
}
