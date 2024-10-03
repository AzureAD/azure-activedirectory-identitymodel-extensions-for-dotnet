// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System.Threading;
using System.Threading.Tasks;
using Microsoft.IdentityModel.TestUtils;
using Microsoft.IdentityModel.Tokens.Saml2;

namespace Microsoft.IdentityModel.Tokens.Saml.Tests
{
#nullable enable
    public partial class Saml2SecurityTokenHandlerTests
    {
        internal static async Task ValidateAndCompareResults(
            Saml2SecurityToken saml2Token,
            TokenValidationParameters tokenValidationParameters,
            ValidateTokenAsyncBaseTheoryData theoryData,
            CompareContext context)
        {
            Saml2SecurityTokenHandler saml2TokenHandler = new Saml2SecurityTokenHandler();

            // Validate the token using TokenValidationParameters
            TokenValidationResult legacyTokenValidationParametersResult =
                await saml2TokenHandler.ValidateTokenAsync(saml2Token.Assertion.CanonicalString, tokenValidationParameters);

            // Validate the token using ValidationParameters
            ValidationResult<ValidatedToken> validationParametersResult =
                await saml2TokenHandler.ValidateTokenAsync(
                    saml2Token,
                    theoryData.ValidationParameters!,
                    theoryData.CallContext,
                    CancellationToken.None);

            // Ensure the validity of the results match the expected result
            if (legacyTokenValidationParametersResult.IsValid != theoryData.ExpectedIsValid)
                context.AddDiff($"tokenValidationParametersResult.IsValid != theoryData.ExpectedIsValid");

            if (validationParametersResult.IsSuccess != theoryData.ExpectedIsValid)
                context.AddDiff($"validationParametersResult.IsSuccess != theoryData.ExpectedIsValid");

            if (theoryData.ExpectedIsValid &&
                legacyTokenValidationParametersResult.IsValid &&
                validationParametersResult.IsSuccess)
            {
                // This should compare the ClaimsPrincipal and ClaimsIdentity from one result against the other but right now we have not defined how we will handle this
                /*IdentityComparer.AreEqual(
                    legacyTokenValidationParametersResult.ClaimsIdentity,
                    validationParametersResult.UnwrapResult().ClaimsIdentity,
                    context);
                IdentityComparer.AreEqual(
                    legacyTokenValidationParametersResult.Claims,
                    validationParametersResult.UnwrapResult().Claims,
                    context);*/
            }
            else
            {
                // Verify the exception provided by the TokenValidationParameters path
                theoryData.ExpectedException.ProcessException(legacyTokenValidationParametersResult.Exception, context);

                if (!validationParametersResult.IsSuccess)
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
