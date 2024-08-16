// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

namespace Microsoft.IdentityModel.Abstractions
{
    /// <summary>
    /// Unit type used to represent the absence of a specific value.
    /// </summary>
    public record struct Unit
    {
        /// <summary>
        /// Returns the default instance of <see cref="Unit"/>.
        /// </summary>
        public static Unit Default { get; }
    }
}
