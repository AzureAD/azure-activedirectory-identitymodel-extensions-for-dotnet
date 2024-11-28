// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Tokens;

namespace Microsoft.IdentityModel.TestUtils.TokenValidationExtensibility.Tests
{
    public partial class ExtensibilityTesting
    {
        public static async Task ValidateTokenAsync_Extensibility(ExtensibilityTheoryData theoryData, object testInstance, string methodName)
        {
            var context = TestUtilities.WriteHeader($"{testInstance}.{methodName}", theoryData);
            context.IgnoreType = false;
            for (int i = 0; i < theoryData.ExtraStackFrames; i++)
                theoryData.ValidationError!.AddStackFrame(new StackFrame(false));

            SecurityToken securityToken = theoryData.TokenHandler.CreateToken(theoryData.SecurityTokenDescriptor!);

            try
            {
                ValidationResult<ValidatedToken> validationResult = await theoryData.TokenHandler.ValidateTokenAsync(
                    securityToken,
                    theoryData.ValidationParameters!,
                    theoryData.CallContext,
                    CancellationToken.None);

                if (validationResult.IsValid)
                {
                    context.AddDiff("validationResult.IsValid == true, expected false");
                }
                else
                {
                    ValidationError validationError = validationResult.UnwrapError();
                    IdentityComparer.AreValidationErrorsEqual(validationError, theoryData.ValidationError, context);
                    theoryData.ExpectedException.ProcessException(validationError.GetException(), context);
                }
            }
            catch (Exception ex)
            {
                context.AddDiff($"ValidateTokenAsync threw an unexpected exception: {ex}.");
            }

            TestUtilities.AssertFailIfErrors(context);
        }
    }
}
