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
            TokenValidationResult legacyTokenValidationParametersResult =
                await jsonWebTokenHandler.ValidateTokenAsync(jwtString, theoryData.TokenValidationParameters);

            // Validate the token using ValidationParameters
            ValidationResult<ValidatedToken> validationParametersResult =
                await jsonWebTokenHandler.ValidateTokenAsync(
                    jwtString, theoryData.ValidationParameters!, theoryData.CallContext, CancellationToken.None);

            // Ensure the validity of the results match the expected result
            if (legacyTokenValidationParametersResult.IsValid != theoryData.ExpectedIsValid)
                context.AddDiff($"tokenValidationParametersResult.IsValid != theoryData.ExpectedIsValid");

            if (validationParametersResult.IsValid != theoryData.ExpectedIsValid)
                context.AddDiff($"validationParametersResult.IsValid != theoryData.ExpectedIsValid");

            if (theoryData.ExpectedIsValid &&
                legacyTokenValidationParametersResult.IsValid &&
                validationParametersResult.IsValid)
            {
                // Compare the ClaimsPrincipal and ClaimsIdentity from one result against the other
                IdentityComparer.AreEqual(
                    legacyTokenValidationParametersResult.ClaimsIdentity,
                    validationParametersResult.UnwrapResult().ClaimsIdentity,
                    context);
                IdentityComparer.AreEqual(
                    legacyTokenValidationParametersResult.Claims,
                    validationParametersResult.UnwrapResult().Claims,
                    context);
            }
            else
            {
                // Verify the exception provided by the TokenValidationParameters path
                theoryData.ExpectedException.ProcessException(legacyTokenValidationParametersResult.Exception, context);

                if (!validationParametersResult.IsValid)
                {
                    // Verify the exception provided by the ValidationParameters path
                    if (theoryData.ExpectedExceptionValidationParameters is not null)
                    {
                        // If there is a special case for the ValidationParameters path, use that.
                        theoryData.ExpectedExceptionValidationParameters
                            .ProcessException(validationParametersResult.UnwrapError().GetException(), context);
                    }
                    else
                    {
                        theoryData.ExpectedException
                            .ProcessException(validationParametersResult.UnwrapError().GetException(), context);

                        // If the expected exception is the same in both paths, verify the message matches
                        IdentityComparer.AreStringsEqual(
                            legacyTokenValidationParametersResult.Exception.Message,
                            validationParametersResult.UnwrapError().GetException().Message,
                            context);
                    }
                }

                // Verify that the exceptions are of the same type.
                IdentityComparer.AreEqual(
                    legacyTokenValidationParametersResult.Exception.GetType(),
                    validationParametersResult.UnwrapError().GetException().GetType(),
                    context);

                if (legacyTokenValidationParametersResult.Exception is SecurityTokenException)
                {
                    // Verify that the custom properties are the same.
                    IdentityComparer.AreSecurityTokenExceptionsEqual(
                        legacyTokenValidationParametersResult.Exception,
                        validationParametersResult.UnwrapError().GetException(),
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
        internal ExpectedException? ExpectedExceptionValidationParameters { get; set; } = null;
    }
}
#nullable restore
