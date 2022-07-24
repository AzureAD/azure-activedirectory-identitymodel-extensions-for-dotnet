// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using Microsoft.IdentityModel.Json.Linq;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Tokens;
using System.Collections.Concurrent;
using System.Globalization;

namespace Microsoft.IdentityModel.JsonWebTokens
{
    // Feature is off pending additional memory tests.
    /*
    internal static class JsonWebTokenManager
    {
        internal static ConcurrentDictionary<string, string> KeyToHeaderCache = new ConcurrentDictionary<string, string>();
        internal static ConcurrentDictionary<string, JObject> RawHeaderToJObjectCache = new ConcurrentDictionary<string, JObject>();

        internal static string GetHeaderCacheKey(SecurityKey securityKey, string algorithm)
        {
            return string.Format(CultureInfo.InvariantCulture, "{0}-{1}-{2}", securityKey.GetType(), securityKey.KeyId, algorithm);
        }

        internal static string GetHeaderCacheKey(SigningCredentials signingCredentials)
        {
            if (signingCredentials == null)
                throw LogHelper.LogArgumentNullException(nameof(signingCredentials));

            return GetHeaderCacheKey(signingCredentials.Key, signingCredentials.Algorithm);
        }
    }
    */
}
