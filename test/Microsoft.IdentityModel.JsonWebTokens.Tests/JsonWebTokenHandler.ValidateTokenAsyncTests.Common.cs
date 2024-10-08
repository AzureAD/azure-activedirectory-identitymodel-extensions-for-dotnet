// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#nullable enable
using System.Threading.Tasks;
using System.Threading;
using Microsoft.IdentityModel.TestUtils;
using Microsoft.IdentityModel.Tokens;

namespace Microsoft.IdentityModel.JsonWebTokens.Tests
{
    public partial class JsonWebTokenHandlerValidateTokenAsyncTests
    {
        internal static async Task ValidateAndCompareResults(
            string jwtString,
            ValidateTokenAsyncBaseTheoryData theoryData,
            CompareContext context)
        {
            JsonWebTokenHandler jsonWebTokenHandler = new JsonWebTokenHandler();

            // Validate the token using TokenValidationParameters
            TokenValidationResult tokenValidationResult =
                await jsonWebTokenHandler.ValidateTokenAsync(jwtString, theoryData.TokenValidationParameters);

            // Validate the token using ValidationParameters
            ValidationResult<ValidatedToken> validationResult =
                await jsonWebTokenHandler.ValidateTokenAsync(
                    jwtString, theoryData.ValidationParameters!, theoryData.CallContext, CancellationToken.None);

            // Ensure the validity of the results match the expected result
            if (tokenValidationResult.IsValid != theoryData.ExpectedIsValid)
                context.AddDiff($"tokenValidationParametersResult.IsValid != theoryData.ExpectedIsValid");

            if (validationResult.IsSuccess != theoryData.ExpectedIsValid)
                context.AddDiff($"validationParametersResult.IsSuccess != theoryData.ExpectedIsValid");

            if (theoryData.ExpectedIsValid &&
                tokenValidationResult.IsValid &&
                validationResult.IsSuccess)
            {
                // Compare the ClaimsPrincipal and ClaimsIdentity from one result against the other
                IdentityComparer.AreEqual(
                    tokenValidationResult.ClaimsIdentity,
                    validationResult.UnwrapResult().ClaimsIdentity,
                    context);
                IdentityComparer.AreEqual(
                    tokenValidationResult.Claims,
                    validationResult.UnwrapResult().Claims,
                    context);
            }
            else
            {
                // Verify the exception provided by the TokenValidationParameters path
                theoryData.ExpectedException.ProcessException(tokenValidationResult.Exception, context);

                if (!validationResult.IsSuccess)
                {
                    // Verify the exception provided by the ValidationParameters path
                    if (theoryData.ExpectedExceptionValidationParameters is not null)
                    {
                        // If there is a special case for the ValidationParameters path, use that.
                        theoryData.ExpectedExceptionValidationParameters
                            .ProcessException(validationResult.UnwrapError().GetException(), context);
                    }
                    else
                    {
                        theoryData.ExpectedException
                            .ProcessException(validationResult.UnwrapError().GetException(), context);

                        // If the expected exception is the same in both paths, verify the message matches
                        IdentityComparer.AreStringsEqual(
                            tokenValidationResult.Exception.Message,
                            validationResult.UnwrapError().GetException().Message,
                            context);
                    }
                }

                // Verify that the exceptions are of the same type.
                IdentityComparer.AreEqual(
                    tokenValidationResult.Exception.GetType(),
                    validationResult.UnwrapError().GetException().GetType(),
                    context);

                if (tokenValidationResult.Exception is SecurityTokenException)
                {
                    // Verify that the custom properties are the same.
                    IdentityComparer.AreSecurityTokenExceptionsEqual(
                        tokenValidationResult.Exception,
                        validationResult.UnwrapError().GetException(),
                        context);
                }
            }
        }
    }

    public class ValidateTokenAsyncBaseTheoryData : TheoryDataBase
    {
        public ValidateTokenAsyncBaseTheoryData(string testId) : base(testId) { }

        internal bool ExpectedIsValid { get; set; } = true;

        internal TokenValidationParameters? TokenValidationParameters { get; set; }

        internal ValidationParameters? ValidationParameters { get; set; }

        // only set if we expect a different message on this path
        internal ExpectedException ExpectedExceptionValidationParameters { get; set; } = ExpectedException.NoExceptionExpected;
    }
}
#nullable restore
