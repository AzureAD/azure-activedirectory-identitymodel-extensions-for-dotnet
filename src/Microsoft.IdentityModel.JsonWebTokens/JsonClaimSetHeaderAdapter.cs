// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Tokens;

namespace Microsoft.IdentityModel.JsonWebTokens
{
    internal class JsonClaimSetHeaderAdapter : IHeaderParameterRetriever
    {
#if !NET45
        private readonly JsonClaimSet _jsonClaimSet;

        /// <summary>
        /// Creates an instance of a <see cref="JsonClaimSetHeaderAdapter"/>
        /// </summary>
        /// <param name="jsonClaimSet">The instance of a <see cref="JsonClaimSet"/> to create the <see cref="JsonClaimSetHeaderAdapter"/> from.</param>
        public JsonClaimSetHeaderAdapter(JsonClaimSet jsonClaimSet)
        {
            _jsonClaimSet = jsonClaimSet ?? throw LogHelper.LogArgumentNullException(nameof(jsonClaimSet));
        }
#else
        private readonly JsonClaimSet45 _jsonClaimSet;

        /// <summary>
        /// Creates an instance of a <see cref="JsonClaimSetHeaderAdapter"/>
        /// </summary>
        /// <param name="jsonClaimSet">The instance of a <see cref="JsonClaimSet45"/> to create the <see cref="JsonClaimSetHeaderAdapter"/> from.</param>
        public JsonClaimSetHeaderAdapter(JsonClaimSet45 jsonClaimSet)
        {
            _jsonClaimSet = jsonClaimSet ?? throw LogHelper.LogArgumentNullException(nameof(jsonClaimSet));
        }
#endif

        /// <inheritdoc/>
        public string GetHeaderParameter(string parameter)
        {
            if (string.IsNullOrEmpty(parameter))
                throw LogHelper.LogArgumentNullException(nameof(parameter));

            return _jsonClaimSet.GetStringValue(parameter);
        }
    }
}
