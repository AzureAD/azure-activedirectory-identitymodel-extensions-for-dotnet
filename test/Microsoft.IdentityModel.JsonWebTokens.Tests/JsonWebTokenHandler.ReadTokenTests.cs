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
        public void ReadToken(TokenReadTheoryData theoryData)
        {
            CompareContext context = TestUtilities.WriteHeader($"{this}.JsonWebTokenHandlerReadTokenTests", theoryData);
            TokenReadResult tokenReadResult = JsonWebTokenHandler.ReadToken(
                theoryData.Token,
                new CallContext());

            if (tokenReadResult.Exception != null)
                theoryData.ExpectedException.ProcessException(tokenReadResult.Exception);
            else
                theoryData.ExpectedException.ProcessNoException();

            IdentityComparer.AreTokenReadResultsEqual(
                tokenReadResult,
                theoryData.TokenReadResult,
                context);

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<TokenReadTheoryData> JsonWebTokenHandlerReadTokenTestCases
        {
            get
            {
                var validToken = EncodedJwts.LiveJwt;
                return new TheoryData<TokenReadTheoryData>
                {
                    new TokenReadTheoryData
                    {
                        TestId = "Valid_Jwt",
                        Token = validToken,
                        TokenReadResult = new TokenReadResult(
                            validToken,
                            new JsonWebToken(validToken))
                    },
                    new TokenReadTheoryData
                    {
                        TestId = "Invalid_NullToken",
                        Token = null,
                        ExpectedException = ExpectedException.ArgumentNullException("IDX10000:"),
                        TokenReadResult = new TokenReadResult(
                            null,
                            ValidationFailureType.NullArgument,
                            new ExceptionDetail(
                                new MessageDetail(
                                    TokenLogMessages.IDX10000,
                                    LogHelper.MarkAsNonPII("token")),
                                ExceptionDetail.ExceptionType.ArgumentNull,
                                new System.Diagnostics.StackFrame()))
                    },
                    new TokenReadTheoryData
                    {
                        TestId = "Invalid_EmptyToken",
                        Token = string.Empty,
                        ExpectedException = ExpectedException.ArgumentNullException("IDX10000:"),
                        TokenReadResult = new TokenReadResult(
                            string.Empty,
                            ValidationFailureType.NullArgument,
                            new ExceptionDetail(
                                new MessageDetail(
                                    TokenLogMessages.IDX10000,
                                    LogHelper.MarkAsNonPII("token")),
                                ExceptionDetail.ExceptionType.ArgumentNull,
                                new System.Diagnostics.StackFrame()))
                    },
                    new TokenReadTheoryData
                    {
                        TestId = "Invalid_MalformedToken",
                        Token = "malformed-token",
                        ExpectedException = ExpectedException.SecurityTokenMalformedTokenException(
                            "IDX14107:",
                            typeof(SecurityTokenMalformedException)),
                        TokenReadResult = new TokenReadResult(
                            "malformed-token",
                            ValidationFailureType.TokenReadFailed,
                            new ExceptionDetail(
                                new MessageDetail(
                                    LogMessages.IDX14107,
                                    LogHelper.MarkAsNonPII("token")),
                                ExceptionDetail.ExceptionType.SecurityTokenMalformed,
                                new System.Diagnostics.StackFrame()))
                    }
                };
            }
        }
    }

    public class TokenReadTheoryData : TheoryDataBase
    {
        public string Token { get; set; }

        public object TokenReadResult { get; set; }
    }
}
