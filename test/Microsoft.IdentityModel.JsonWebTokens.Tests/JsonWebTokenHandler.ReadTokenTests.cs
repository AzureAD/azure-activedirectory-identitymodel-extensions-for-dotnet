// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.IdentityModel.Tokens.Jwt.Tests;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.TestUtils;
using Microsoft.IdentityModel.Tokens;
using Xunit;
using TokenLogMessages = Microsoft.IdentityModel.Tokens.LogMessages;

namespace Microsoft.IdentityModel.JsonWebTokens.Tests
{
    public class JsonWebTokenHandlerReadTokenTests
    {
        [Theory, MemberData(nameof(JsonWebTokenHandlerReadTokenTestCases), DisableDiscoveryEnumeration = true)]
        public void ReadToken(TokenReadingTheoryData theoryData)
        {
            CompareContext context = TestUtilities.WriteHeader($"{this}.JsonWebTokenHandlerReadTokenTests", theoryData);
            ValidationResult<SecurityToken> result = JsonWebTokenHandler.ReadToken(
                theoryData.Token,
                new CallContext());

            if (result.IsSuccess)
            {
                IdentityComparer.AreEqual(result.UnwrapResult(),
                    theoryData.Result.UnwrapResult(),
                    context);

                theoryData.ExpectedException.ProcessNoException(context);
            }
            else
            {
                ValidationError validationError = result.UnwrapError();
                IdentityComparer.AreStringsEqual(
                    validationError.FailureType.Name,
                    theoryData.Result.UnwrapError().FailureType.Name,
                    context);

                Exception exception = validationError.GetException();
                theoryData.ExpectedException.ProcessException(exception, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        [Fact]
        public void ReadToken_ThrowsIfAccessingSecurityTokenOnFailedRead()
        {
            ValidationResult<SecurityToken> result = JsonWebTokenHandler.ReadToken(
                null,
                new CallContext());

            Assert.Throws<InvalidOperationException>(() => result.UnwrapResult());
        }

        public static TheoryData<TokenReadingTheoryData> JsonWebTokenHandlerReadTokenTestCases
        {
            get
            {
                var validToken = EncodedJwts.LiveJwt;
                return new TheoryData<TokenReadingTheoryData>
                {
                    new TokenReadingTheoryData
                    {
                        TestId = "Valid_Jwt",
                        Token = validToken,
                        Result = new JsonWebToken(validToken),
                    },
                    new TokenReadingTheoryData
                    {
                        TestId = "Invalid_NullToken",
                        Token = null,
                        ExpectedException = ExpectedException.SecurityTokenArgumentNullException("IDX10000:"),
                        Result = new ValidationError(
                            new MessageDetail(
                                TokenLogMessages.IDX10000,
                                LogHelper.MarkAsNonPII("token")),
                            ValidationFailureType.NullArgument,
                            typeof(SecurityTokenArgumentNullException),
                            null)
                    },
                    new TokenReadingTheoryData
                    {
                        TestId = "Invalid_EmptyToken",
                        Token = string.Empty,
                        ExpectedException = ExpectedException.SecurityTokenArgumentNullException("IDX10000:"),
                        Result = new ValidationError(
                            new MessageDetail(
                                TokenLogMessages.IDX10000,
                                LogHelper.MarkAsNonPII("token")),
                            ValidationFailureType.NullArgument,
                            typeof(SecurityTokenArgumentNullException),
                            null)
                    },
                    new TokenReadingTheoryData
                    {
                        TestId = "Invalid_MalformedToken",
                        Token = "malformed-token",
                        ExpectedException = ExpectedException.SecurityTokenMalformedTokenException(
                            "IDX14107:",
                            typeof(SecurityTokenMalformedException)),
                        Result = new ValidationError(
                            new MessageDetail(
                                LogMessages.IDX14107,
                                LogHelper.MarkAsNonPII("token")),
                            ValidationFailureType.TokenReadingFailed,
                            typeof(SecurityTokenMalformedException),
                            null,
                            new SecurityTokenMalformedException()),
                    }
                };
            }
        }
    }

    public class TokenReadingTheoryData : TheoryDataBase
    {
        public string Token { get; set; }
        internal ValidationResult<SecurityToken> Result { get; set; }
    }
}
