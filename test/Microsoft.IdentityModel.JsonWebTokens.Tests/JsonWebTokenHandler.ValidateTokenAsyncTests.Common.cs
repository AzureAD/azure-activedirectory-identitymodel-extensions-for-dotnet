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
            TokenValidationResult legacyTokenValidationParametersResult =
                await jsonWebTokenHandler.ValidateTokenAsync(jwtString, theoryData.TokenValidationParameters);
            ValidationResult<ValidatedToken> validationParametersResult =
                await jsonWebTokenHandler.ValidateTokenAsync(
                    jwtString, theoryData.ValidationParameters!, theoryData.CallContext, CancellationToken.None);

            if (legacyTokenValidationParametersResult.IsValid != theoryData.ExpectedIsValid)
                context.AddDiff($"tokenValidationParametersResult.IsValid != theoryData.ExpectedIsValid");

            if (validationParametersResult.IsSuccess != theoryData.ExpectedIsValid)
                context.AddDiff($"validationParametersResult.IsSuccess != theoryData.ExpectedIsValid");

            if (theoryData.ExpectedIsValid &&
                legacyTokenValidationParametersResult.IsValid &&
                validationParametersResult.IsSuccess)
            {
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
                theoryData.ExpectedException.ProcessException(legacyTokenValidationParametersResult.Exception, context);

                if (!validationParametersResult.IsSuccess)
                {
                    // If there is a special case for the ValidationParameters path, use that.
                    if (theoryData.ExpectedExceptionValidationParameters is not null)
                        theoryData.ExpectedExceptionValidationParameters
                            .ProcessException(validationParametersResult.UnwrapError().GetException(), context);
                    else
                        theoryData.ExpectedException
                            .ProcessException(validationParametersResult.UnwrapError().GetException(), context);
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
