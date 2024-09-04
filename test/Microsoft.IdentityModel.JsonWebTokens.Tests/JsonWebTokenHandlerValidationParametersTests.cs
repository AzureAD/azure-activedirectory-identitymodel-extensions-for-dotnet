// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

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
        [Theory, MemberData(nameof(JsonWebTokenHandlerValidationParametersTestCases))]
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
                    Audience = theoryData.Audience,
                    Issuer = theoryData.Issuer,
                };

                jwtString = jsonWebTokenHandler.CreateToken(securityTokenDescriptor);
            }

            TokenValidationResult tokenValidationParametersResult =
                await jsonWebTokenHandler.ValidateTokenAsync(jwtString, theoryData.TokenValidationParameters);
            Result<ValidationResult> validationParametersResult =
                await jsonWebTokenHandler.ValidateTokenAsync(
                    jwtString, theoryData.ValidationParameters, new CallContext(), CancellationToken.None);

            if (tokenValidationParametersResult.IsValid != theoryData.ExpectedIsValid)
                context.AddDiff($"tokenValidationResult.IsValid != theoryData.ExpectedIsValid");

            if (validationParametersResult.IsSuccess != theoryData.ExpectedIsValid)
                context.AddDiff($"result.IsSuccess != theoryData.ExpectedIsValid");

            if (theoryData.ExpectedIsValid)
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
                    new JsonWebTokenHandlerValidationParametersTheoryData
                    {
                        TestId = "Valid",
                        TokenValidationParameters = CreateTokenValidationParameters(
                            Default.Issuer, [Default.Audience], Default.AsymmetricSigningKey),
                        ValidationParameters = CreateValidationParameters(
                            Default.Issuer, [Default.Audience], Default.AsymmetricSigningKey),
                    },
                    new JsonWebTokenHandlerValidationParametersTheoryData
                    {
                        TestId = "Invalid_MalformedToken",
                        TokenString = "malformedToken",
                        TokenValidationParameters = CreateTokenValidationParameters(
                            Default.Issuer, [Default.Audience], Default.AsymmetricSigningKey),
                        ValidationParameters = CreateValidationParameters(
                            Default.Issuer, [Default.Audience], Default.AsymmetricSigningKey),
                        ExpectedIsValid = false,
                        ExpectedException = ExpectedException.SecurityTokenMalformedException("IDX14100:"),
                        ExpectedExceptionValidationParameters = ExpectedException.SecurityTokenMalformedException("IDX14107:", typeof(SecurityTokenMalformedException)),
                    },
                    new JsonWebTokenHandlerValidationParametersTheoryData
                    {
                        TestId = "Invalid_Issuer",
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
                    new JsonWebTokenHandlerValidationParametersTheoryData
                    {
                        TestId = "Invalid_Audience",
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
                    new JsonWebTokenHandlerValidationParametersTheoryData
                    {
                        TestId = "Invalid_TokenNotSigned",
                        TokenValidationParameters = CreateTokenValidationParameters(
                            Default.Issuer, [Default.Audience], Default.AsymmetricSigningKey),
                        ValidationParameters = CreateValidationParameters(
                            Default.Issuer, [Default.Audience], Default.AsymmetricSigningKey),
                        SigningCredentials = null,
                        ExpectedIsValid = false,
                        ExpectedException = ExpectedException.SecurityTokenInvalidSignatureException("IDX10504:"),
                    },
                    new JsonWebTokenHandlerValidationParametersTheoryData
                    {
                        TestId = "Invalid_TokenSignedWithDifferentKey_KeyIdPresent_TryAllKeysFalse",
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
                    new JsonWebTokenHandlerValidationParametersTheoryData
                    {
                        TestId = "Invalid_TokenSignedWithDifferentKey_KeyIdPresent_TryAllKeysTrue",
                        TokenValidationParameters = CreateTokenValidationParameters(
                            Default.Issuer, [Default.Audience], Default.AsymmetricSigningKey, tryAllKeys: true),
                        ValidationParameters = CreateValidationParameters(
                            Default.Issuer, [Default.Audience], Default.AsymmetricSigningKey, tryAllKeys: true),
                        SigningCredentials = Default.SymmetricSigningCredentials,
                        ExpectedIsValid = false,
                        ExpectedException = ExpectedException.SecurityTokenSignatureKeyNotFoundException("IDX10503:"),
                    },
                    new JsonWebTokenHandlerValidationParametersTheoryData
                    {
                        TestId = "Invalid_TokenSignedWithDifferentKey_KeyIdNotPresent_TryAllKeysFalse",
                        TokenValidationParameters = CreateTokenValidationParameters(
                            Default.Issuer, [Default.Audience], Default.AsymmetricSigningKey),
                        ValidationParameters = CreateValidationParameters(
                            Default.Issuer, [Default.Audience], Default.AsymmetricSigningKey),
                        SigningCredentials = KeyingMaterial.DefaultSymmetricSigningCreds_256_Sha2_NoKeyId,
                        ExpectedIsValid = false,
                        ExpectedException = ExpectedException.SecurityTokenSignatureKeyNotFoundException("IDX10500:"),
                    },
                    new JsonWebTokenHandlerValidationParametersTheoryData
                    {
                        TestId = "Invalid_TokenSignedWithDifferentKey_KeyIdNotPresent_TryAllKeysTrue",
                        TokenValidationParameters = CreateTokenValidationParameters(
                            Default.Issuer, [Default.Audience], Default.AsymmetricSigningKey, tryAllKeys: true),
                        ValidationParameters = CreateValidationParameters(
                            Default.Issuer, [Default.Audience], Default.AsymmetricSigningKey, tryAllKeys: true),
                        SigningCredentials = KeyingMaterial.DefaultSymmetricSigningCreds_256_Sha2_NoKeyId,
                        ExpectedIsValid = false,
                        ExpectedException = ExpectedException.SecurityTokenSignatureKeyNotFoundException("IDX10517:"),
                    },
                };

                static TokenValidationParameters CreateTokenValidationParameters(
                    string issuer,
                    List<string> audiences,
                    SecurityKey issuerSigningKey,
                    bool tryAllKeys = false) => new TokenValidationParameters
                    {
                        ValidateAudience = true,
                        ValidateIssuer = true,
                        ValidateLifetime = true,
                        ValidateTokenReplay = true,
                        ValidateIssuerSigningKey = true,
                        IssuerSigningKey = issuerSigningKey,
                        ValidAudiences = audiences,
                        ValidIssuer = issuer,
                        TryAllIssuerSigningKeys = tryAllKeys,
                    };

                static ValidationParameters CreateValidationParameters(
                    string issuer,
                    List<string> audiences,
                    SecurityKey issuerSigningKey,
                    bool tryAllKeys = false)
                {
                    ValidationParameters validationParameters = new ValidationParameters();
                    validationParameters.ValidIssuers.Add(issuer);
                    audiences.ForEach(audience => validationParameters.ValidAudiences.Add(audience));
                    validationParameters.IssuerSigningKeys.Add(issuerSigningKey);
                    validationParameters.TryAllIssuerSigningKeys = tryAllKeys;

                    return validationParameters;
                }
            }
        }

        public class JsonWebTokenHandlerValidationParametersTheoryData : TheoryDataBase
        {
            public string TokenString { get; internal set; } = null;
            public SigningCredentials SigningCredentials { get; internal set; } = Default.AsymmetricSigningCredentials;
            public EncryptingCredentials EncryptingCredentials { get; internal set; }
            public IDictionary<string, object> AdditionalHeaderParams { get; internal set; }
            public ClaimsIdentity Subject { get; internal set; } = Default.ClaimsIdentity;
            public string Audience { get; internal set; } = Default.Audience;
            public string Issuer { get; internal set; } = Default.Issuer;
            internal bool ExpectedIsValid { get; set; } = true;
            internal TokenValidationParameters TokenValidationParameters { get; set; }
            internal ValidationParameters ValidationParameters { get; set; }

            // only set if we expect a different message on this path
            internal ExpectedException ExpectedExceptionValidationParameters { get; set; } = null;
        }
    }
}
