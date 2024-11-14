// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using Xunit;
using Microsoft.IdentityModel.TestUtils;
using TokenLogMessages = Microsoft.IdentityModel.Tokens.LogMessages;
using Microsoft.IdentityModel.Logging;

namespace Microsoft.IdentityModel.Tokens.Saml2.Tests
{
    public partial class Saml2SecurityTokenHandlerTests
    {
        [Theory, MemberData(nameof(ReadTokenTestCases), DisableDiscoveryEnumeration = true)]
        public void ReadToken_ResultType(TokenReadingTheoryData theoryData)
        {
            CompareContext context = TestUtilities.WriteHeader($"{this}.ReadToken_ResultType", theoryData);
            Saml2SecurityTokenHandler handler = new Saml2SecurityTokenHandler();
            ValidationResult<Saml2SecurityToken> result = handler.ReadSaml2Token(
                theoryData.Token,
                new CallContext());

            if (result.IsValid)
            {
                IdentityComparer.AreEqual(
                    result.UnwrapResult(),
                    handler.ReadToken(theoryData.Token),
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

        public static TheoryData<TokenReadingTheoryData> ReadTokenTestCases
        {
            get
            {
                var theoryData = new TheoryData<TokenReadingTheoryData>();

                theoryData.Add(new TokenReadingTheoryData("Valid_SAML_Token")
                {
                    Token = ReferenceTokens.Saml2Token_Valid,
                });

                theoryData.Add(new TokenReadingTheoryData("Invalid_NullToken")
                {
                    Token = null,
                    ExpectedException = ExpectedException.SecurityTokenArgumentNullException("IDX10000:"),
                    Result = new ValidationError(
                        new MessageDetail(
                            TokenLogMessages.IDX10000,
                            LogHelper.MarkAsNonPII("token")),
                        ValidationFailureType.NullArgument,
                        typeof(SecurityTokenArgumentNullException),
                        null)
                });

                theoryData.Add(new TokenReadingTheoryData("Invalid_EmptyToken")
                {
                    Token = string.Empty,
                    ExpectedException = ExpectedException.SecurityTokenArgumentNullException("IDX10000:"),
                    Result = new ValidationError(
                        new MessageDetail(
                            TokenLogMessages.IDX10000,
                            LogHelper.MarkAsNonPII("token")),
                        ValidationFailureType.NullArgument,
                        typeof(SecurityTokenArgumentNullException),
                        null)
                });

                theoryData.Add(new TokenReadingTheoryData("Invalid_MalformedToken")
                {
                    Token = ReferenceTokens.Saml2Token_MissingVersion,
                    ExpectedException = ExpectedException.Saml2SecurityTokenReadException("IDX13003:", inner: typeof(Saml2SecurityTokenReadException)),
                    Result = new ValidationError(
                        new MessageDetail(LogMessages.IDX13003, "exception message"),
                        ValidationFailureType.TokenReadingFailed,
                        typeof(Saml2SecurityTokenReadException),
                        null),
                });

                return theoryData;
            }
        }
    }

    public class TokenReadingTheoryData : TheoryDataBase
    {
        public TokenReadingTheoryData(string testId)
        {
            TestId = testId;
        }

        public string Token { get; set; }

        internal ValidationResult<SecurityToken> Result { get; set; }
    }
}
