// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Tokens;

namespace Microsoft.IdentityModel.JsonWebTokens
{
    /// <summary>
    /// An adapter for <see cref="JsonWebToken"/> to <see cref="IHeaderParameterAndPayloadClaimRetriever"/>
    /// </summary>
    public class JsonWebTokenHeaderParameterAndClaimRetrieverAdapter : IHeaderParameterAndPayloadClaimRetriever
    {
        /// <summary>
        /// Creates an instance of a <see cref="JsonWebTokenHeaderParameterAndClaimRetrieverAdapter"/>
        /// </summary>
        /// <param name="jsonWebToken">The <see cref="JsonWebToken"/> to create the <see cref="IHeaderParameterAndPayloadClaimRetriever"/> from.</param>
        public JsonWebTokenHeaderParameterAndClaimRetrieverAdapter(JsonWebToken jsonWebToken)
        {
            _jsonWebToken = jsonWebToken ?? throw LogHelper.LogArgumentNullException(nameof(jsonWebToken));

            HeaderParameters = new JsonClaimSetHeaderAdapter(jsonWebToken.Header);
            PayloadClaims = new JsonClaimSetPayloadAdapter(jsonWebToken.Payload);

            if (jsonWebToken.InnerToken != null)
                InnerHeaderParameterAndClaimRetriever = new JsonWebTokenHeaderParameterAndClaimRetrieverAdapter(jsonWebToken.InnerToken);
        }

        private readonly JsonWebToken _jsonWebToken;

        /// <inheritdoc/>
        public IHeaderParameterRetriever HeaderParameters { get; }

        /// <inheritdoc/>
        public IPayloadClaimRetriever PayloadClaims { get; }

        /// <inheritdoc/>
        public IHeaderParameterAndPayloadClaimRetriever InnerHeaderParameterAndClaimRetriever { get; }

        /// <inheritdoc/>
        public string GetStringRepresentation() => _jsonWebToken.EncodedToken;

        /// <inheritdoc/>
        /// <remarks>
        /// Format is inheritted from JwtSecurityToken.ToString()
        /// </remarks>
        public override string ToString()
        {
            if (_jsonWebToken.Payload != null)
                return _jsonWebToken.Header.RootElement.ToString() + "." + _jsonWebToken.Payload.RootElement.ToString();
            else
                return _jsonWebToken.Header.RootElement.ToString() + ".";
        }
    }
}
