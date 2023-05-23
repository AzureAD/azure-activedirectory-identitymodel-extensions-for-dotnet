// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Tokens;

#if NET45
using Microsoft.IdentityModel.Json.Linq;
#else
using System.Text.Json;
#endif

namespace Microsoft.IdentityModel.JsonWebTokens
{
    internal class JsonClaimSetPayloadAdapter : IPayloadClaimRetriever
    {
#if !NET45
        private readonly JsonClaimSet _jsonClaimSet;

        /// <summary>
        /// Creates an instance of an <see cref="JsonClaimSetPayloadAdapter"/>
        /// </summary>
        /// <param name="jsonClaimSet">The <see cref="JsonClaimSet"/> to create the <see cref="JsonClaimSetPayloadAdapter"/></param>
        public JsonClaimSetPayloadAdapter(JsonClaimSet jsonClaimSet)
        {
            _jsonClaimSet = jsonClaimSet ?? throw LogHelper.LogArgumentNullException(nameof(jsonClaimSet));
        }
#else
        private readonly JsonClaimSet45 _jsonClaimSet;

        /// <summary>
        /// Creates an instance of an <see cref="JsonClaimSetPayloadAdapter"/>
        /// </summary>
        /// <param name="jsonClaimSet">The <see cref="JsonClaimSet45"/> to create the <see cref="JsonClaimSetPayloadAdapter"/></param>
        public JsonClaimSetPayloadAdapter(JsonClaimSet45 jsonClaimSet)
        {
            _jsonClaimSet = jsonClaimSet ?? throw LogHelper.LogArgumentNullException(nameof(jsonClaimSet));
        }
#endif

        /// <inheritdoc/>
        public DateTime GetDateTimeValue(string claimType)
        {
            if (string.IsNullOrEmpty(claimType))
                throw LogHelper.LogArgumentNullException(nameof(claimType));

            return _jsonClaimSet.GetDateTime(claimType);
        }

        /// <inheritdoc/>
        public IList<string> GetStringCollection(string claimType)
        {
            if (string.IsNullOrEmpty(claimType))
                throw LogHelper.LogArgumentNullException(nameof(claimType));

            var result = new List<string>();

#if NET45
            if (_jsonClaimSet.TryGetValue(claimType, out JToken value))
            {
                if (value.Type is JTokenType.String)
                    result = new List<string> { value.ToObject<string>() };
                else if (value.Type is JTokenType.Array)
                    result = value.ToObject<List<string>>();
            }
#else
            if (_jsonClaimSet.TryGetValue(claimType, out JsonElement audiences))
            {
                if (audiences.ValueKind == JsonValueKind.String)
                    result = new List<string> { audiences.GetString() };

                if (audiences.ValueKind == JsonValueKind.Array)
                {
                    foreach (JsonElement jsonElement in audiences.EnumerateArray())
                        result.Add(jsonElement.ToString());
                }
            }
#endif

            return result;
        }

        /// <inheritdoc/>
        public string GetStringValue(string claimType)
        {
            if (string.IsNullOrEmpty(claimType))
                throw LogHelper.LogArgumentNullException(nameof(claimType));

            return _jsonClaimSet.GetStringValue(claimType);
        }

        /// <inheritdoc/>
        public bool TryGetValue(string claimType, out object value)
        {
            if (string.IsNullOrEmpty(claimType))
                throw LogHelper.LogArgumentNullException(nameof(claimType));

            return _jsonClaimSet.TryGetValue(claimType, out value);
        }
    }
}
