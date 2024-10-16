// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

namespace Microsoft.IdentityModel.Tokens
{
    /// <summary>
    /// Unit type used to represent an empty value in ValidationResults.
    /// </summary>
    /// <remarks>All copies of TokenValidationUnit are considered equal.</remarks>
    internal record struct TokenValidationUnit
    {
        internal static TokenValidationUnit Default { get; }
    }
}
