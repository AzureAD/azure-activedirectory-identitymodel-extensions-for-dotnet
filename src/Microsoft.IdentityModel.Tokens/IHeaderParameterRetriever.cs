// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

namespace Microsoft.IdentityModel.Tokens
{
    /// <summary>
    /// Represents an object capable of retrieving values from a header.
    /// </summary>
    public interface IHeaderParameterRetriever
    {
        /// <summary>
        /// Gets a header parameter.
        /// </summary>
        /// <param name="parameter">The name of the header parameter.</param>
        /// <returns>The value of the header parameter or an empty string if not found.</returns>
        public string GetHeaderParameter(string parameter);
    }
}
