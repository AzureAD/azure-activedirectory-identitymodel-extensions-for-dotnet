// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

namespace Microsoft.IdentityModel.Tokens
{
    /// <summary>
    /// Represents an object that can get values from both a header and a payload.
    /// </summary>
    public interface IHeaderParameterAndPayloadClaimRetriever
    {
        /// <summary>
        /// Gets the header parameter retriever.
        /// </summary>
        public IHeaderParameterRetriever HeaderParameters { get; }

        /// <summary>
        /// Gets the payload claims retriever.
        /// </summary>
        public IPayloadClaimRetriever PayloadClaims { get; }

        /// <summary>
        /// Gets the inner header and payload claims retriever.
        /// </summary>
        public IHeaderParameterAndPayloadClaimRetriever InnerHeaderParameterAndClaimRetriever { get; }
    }
}
