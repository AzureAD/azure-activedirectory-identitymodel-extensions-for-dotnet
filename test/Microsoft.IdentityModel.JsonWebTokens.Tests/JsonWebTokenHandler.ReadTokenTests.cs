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
            Result<SecurityToken> result = JsonWebTokenHandler.ReadToken(
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
                ExceptionDetail exceptionDetail = result.UnwrapError();
                IdentityComparer.AreStringsEqual(
                    exceptionDetail.FailureType.Name,
                    theoryData.Result.UnwrapError().FailureType.Name,
                    context);

                Exception exception = exceptionDetail.GetException();
                theoryData.ExpectedException.ProcessException(exception, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        [Fact]
        public void ReadToken_ThrowsIfAccessingSecurityTokenOnFailedRead()
        {
            Result<SecurityToken> result = JsonWebTokenHandler.ReadToken(
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
                        ExpectedException = ExpectedException.ArgumentNullException("IDX10000:"),
                        Result = new ExceptionDetail(
                            new MessageDetail(
                                TokenLogMessages.IDX10000,
                                LogHelper.MarkAsNonPII("token")),
                            ValidationFailureType.NullArgument,
                            typeof(ArgumentNullException),
                            null,
                            null)
                    },
                    new TokenReadingTheoryData
                    {
                        TestId = "Invalid_EmptyToken",
                        Token = string.Empty,
                        ExpectedException = ExpectedException.ArgumentNullException("IDX10000:"),
                        Result = new ExceptionDetail(
                            new MessageDetail(
                                TokenLogMessages.IDX10000,
                                LogHelper.MarkAsNonPII("token")),
                            ValidationFailureType.NullArgument,
                            typeof(ArgumentNullException),
                            null,
                            null)
                    },
                    new TokenReadingTheoryData
                    {
                        TestId = "Invalid_MalformedToken",
                        Token = "malformed-token",
                        ExpectedException = ExpectedException.SecurityTokenMalformedTokenException(
                            "IDX14107:",
                            typeof(SecurityTokenMalformedException)),
                        Result = new ExceptionDetail(
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
        internal Result<SecurityToken> Result { get; set; }
    }
}
