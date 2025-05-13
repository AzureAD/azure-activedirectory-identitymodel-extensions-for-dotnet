// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Text.Json;
using Microsoft.IdentityModel.Tokens.Json;

namespace Microsoft.IdentityModel.JsonWebTokens
{
    /// <summary>
    /// Defines a ClaimsIdentity that knows how to fish claims out of JsonWebToken
    /// </summary>
#pragma warning disable RS0016 // Add public types and members to the declared API
    public class JwtClaimsIdentity : ClaimsIdentity
    {
        JsonWebToken _jwt;

        /// <summary>
        /// Creates a new instance of <see cref="JwtClaimsIdentity"/>.
        /// </summary>
        public JwtClaimsIdentity(JsonWebToken jwt)
        {
            _jwt = jwt;
        }

        /// <summary>
        /// Returns a value that indicates whether the <see cref="ClaimsIdentity"/> contains a claim of the specified type and value.
        /// </summary>
        /// <param name="type">the claim name.</param>
        /// <param name="value">the claims value.</param>
        /// <returns></returns>
        public override bool HasClaim(string type, string value)
        {
            if (!_jwt.Payload._jsonClaims.TryGetValue(type, out object obj))
                return false;

            if (obj is string str)
            {
                return string.Equals(str, value, StringComparison.Ordinal);
            }
            else if (obj is string[] strArray)
            {
                foreach (string s in strArray)
                {
                    if (string.Equals(s, value, StringComparison.Ordinal))
                        return true;
                }
            }
            else if (obj is JsonElement jsonElement)
            {
                if (JsonSerializerPrimitives.TryCreateTypeFromJsonElement<IList<string>>(jsonElement, out IList<string> strings))
                {
                    if (strings != null)
                    {
                        foreach (string s in strings)
                        {
                            if (string.Equals(s, value, StringComparison.Ordinal))
                                return true;
                        }
                    }
                }
            }

            return false;
        }
    }
#pragma warning restore RS0016 // Add public types and members to the declared API
}
