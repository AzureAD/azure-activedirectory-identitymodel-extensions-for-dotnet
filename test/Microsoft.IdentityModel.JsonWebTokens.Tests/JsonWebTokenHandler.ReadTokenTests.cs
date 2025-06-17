// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.IdentityModel.Tokens.Jwt.Tests;
using Microsoft.Identity.Abstractions;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.TestUtils;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Tokens.Experimental;
using Xunit;
using TokenLogMessages = Microsoft.IdentityModel.Tokens.LogMessages;

namespace Microsoft.IdentityModel.JsonWebTokens.Tests
{
    public class JsonWebTokenHandlerReadTokenTests
    {
        [Theory, MemberData(nameof(JsonWebTokenHandlerReadTokenTestCases), DisableDiscoveryEnumeration = true)]
        public void ReadToken(TokenReadingTheoryData theoryData)
        {
            CompareContext context = TestUtilities.WriteHeader($"{this}.ReadToken", theoryData);
            OperationResult<SecurityToken, ValidationError> operationResult = JsonWebTokenHandler.ReadToken(
                theoryData.Token,
                new CallContext());

            if (operationResult.Succeeded)
            {
                IdentityComparer.AreEqual(operationResult.Result,
                    theoryData.OperationResult.Result,
                    context);

                theoryData.ExpectedException.ProcessNoException(context);
            }
            else
            {
                ValidationError validationError = operationResult.Error;
                IdentityComparer.AreStringsEqual(
                    validationError.FailureType.Name,
                    theoryData.OperationResult.Error.FailureType.Name,
                    context);

                Exception exception = validationError.GetException();
                theoryData.ExpectedException.ProcessException(exception, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        [Fact]
        public void ReadToken_ThrowsIfAccessingSecurityTokenOnFailedRead()
        {
            OperationResult<SecurityToken, ValidationError> OperationResult = JsonWebTokenHandler.ReadToken(
                null,
                new CallContext());

            // TODO what is this test for?
        }

        public static TheoryData<TokenReadingTheoryData> JsonWebTokenHandlerReadTokenTestCases
        {
            get
            {
                var validToken = EncodedJwts.LiveJwt;
                return new TheoryData<TokenReadingTheoryData>
                {
                    new TokenReadingTheoryData("Valid_Jwt")
                    {
                        Token = validToken,
                        OperationResult = new JsonWebToken(validToken),
                    },
                    new TokenReadingTheoryData("Invalid_NullToken")
                    {
                        Token = null,
                        ExpectedException = ExpectedException.SecurityTokenArgumentNullException("IDX10000:"),
                        OperationResult = new ValidationError(
                            new MessageDetail(
                                TokenLogMessages.IDX10000,
                                LogHelper.MarkAsNonPII("token")),
                            ValidationFailureType.NullArgument,
                            null)
                    },
                    new TokenReadingTheoryData("Invalid_EmptyToken")
                    {
                        Token = string.Empty,
                        ExpectedException = ExpectedException.SecurityTokenArgumentNullException("IDX10000:"),
                        OperationResult = new ValidationError(
                            new MessageDetail(
                                TokenLogMessages.IDX10000,
                                LogHelper.MarkAsNonPII("token")),
                            ValidationFailureType.NullArgument,
                            null)
                    },
                    new TokenReadingTheoryData("Invalid_MalformedToken")
                    {
                        Token = "malformed-token",
                        ExpectedException = ExpectedException.SecurityTokenMalformedTokenException(
                            "IDX14107:",
                            typeof(SecurityTokenMalformedException)),
                        OperationResult = new ValidationError(
                            new MessageDetail(
                                LogMessages.IDX14107,
                                LogHelper.MarkAsNonPII("token")),
                            ValidationFailureType.TokenReadingFailed,
                            null,
                            new SecurityTokenMalformedException()),
                    }
                };
            }
        }
    }

    public class TokenReadingTheoryData : TheoryDataBase
    {
        public TokenReadingTheoryData(string testId) : base(testId) { }
        public string Token { get; set; }
        internal OperationResult<SecurityToken, ValidationError> OperationResult { get; set; }
    }
}
