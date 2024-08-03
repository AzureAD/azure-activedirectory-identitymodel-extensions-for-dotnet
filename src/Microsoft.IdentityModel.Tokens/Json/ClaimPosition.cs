// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

namespace Microsoft.IdentityModel.Tokens.Json
{
    /// <summary>
    /// Represents the position of the claim value in the token bytes
    /// </summary>
    /// <param name="startIndex">The start index of the claim value (not including the quotes).</param>
    /// <param name="length">The length of the claim value (not including the quotes).</param>
    /// <param name="isEscaped">Indicates if the value bytes are escaped and need to be unescaped before returning the claim value.</param>
    internal class ClaimPosition(int startIndex, int length, bool isEscaped)
    {
        /// <summary>
        /// The start index of the claim value (not including the quotes).
        /// </summary>
        public int StartIndex { get; set; } = startIndex;

        /// <summary>
        /// The length of the claim value (not including the quotes).
        /// </summary>
        public int Length { get; set; } = length;

        /// <summary>
        /// Indicates if the value bytes are escaped and need to be unescaped before returning the claim value.
        /// </summary>
        public bool IsEscaped { get; set; } = isEscaped;
    }
}
