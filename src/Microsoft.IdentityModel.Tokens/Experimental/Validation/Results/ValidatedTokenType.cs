// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#nullable enable
namespace Microsoft.IdentityModel.Tokens.Experimental
{
    /// <summary>
    /// Represents a validated token type, including the number of valid types present in the validation parameters.
    /// </summary>
    public class ValidatedTokenType
    {
        /// <summary>
        /// Initializes a new instance of <see cref="ValidatedTokenType"/>.
        /// </summary>
        /// <param name="type">The token type that was validated.</param>
        /// <param name="validTypeCount">The number of valid types present in the validation parameters.</param>
        public ValidatedTokenType(string type, int validTypeCount)
        {
            Type = type;
            ValidTypeCount = validTypeCount;
        }

        /// <summary>
        /// The token type that was validated.
        /// </summary>
        public string Type { get; }

        /// <summary>
        /// The number of valid types present in the validation parameters.
        /// </summary>
        public int ValidTypeCount { get; }

        /// <summary>
        /// The validated token type's string representation.
        /// </summary>
        /// <returns>A string representing the validated token type and the amount of valid types.</returns>
        public override string ToString() => $"{Type} ({ValidTypeCount} valid types)";
    }
}
#nullable restore
