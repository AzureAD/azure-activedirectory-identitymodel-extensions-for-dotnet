// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System.Diagnostics;

#nullable enable
namespace Microsoft.IdentityModel.Tokens.Saml
{
    public partial class SamlSecurityTokenHandler : SecurityTokenHandler
    {
        // Cached stack frames to build exceptions from validation errors
        internal static class StackFrames
        {
            // Stack frames from ValidateTokenAsync using SecurityToken
            internal static StackFrame? TokenNull;
            internal static StackFrame? TokenValidationParametersNull;

            // Stack frames from ValidateConditions
            internal static StackFrame? AudienceValidationFailed;
            internal static StackFrame? AssertionNull;
            internal static StackFrame? AssertionConditionsNull;
            internal static StackFrame? AssertionConditionsValidationFailed;
            internal static StackFrame? LifetimeValidationFailed;
            internal static StackFrame? OneTimeUseValidationFailed;
        }
    }
}
#nullable restore
