// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Text.Json;

namespace Microsoft.IdentityModel.JsonWebTokens.Tests
{
    public class CustomJsonWebToken : JsonWebToken
    {
        // Represents claims known to this custom implementation and not to the IdentityModel.
        public const string CustomClaimName = "CustomClaim";

        private CustomClaim _customClaim;

        public CustomClaim CustomClaim
        {
            get
            {
                _customClaim ??= Payload.GetValue<CustomClaim>(CustomClaimName);
                return _customClaim;
            }
        }

        public CustomJsonWebToken(string jwtEncodedString) : base(jwtEncodedString) { }

        public CustomJsonWebToken(ReadOnlyMemory<char> encodedTokenMemory) : base(encodedTokenMemory) { }

        public CustomJsonWebToken(string header, string payload) : base(header, payload) { }

        private protected override void ReadPayloadValue(ref Utf8JsonReader reader, IDictionary<string, object> claims)
        {
            // Handle custom claims.
            if (reader.ValueTextEquals(CustomClaimName))
            {
                // Deserialize the custom object claim in an appropriate way.
                reader.Read(); // Move to the value.
                _customClaim = JsonSerializer.Deserialize<CustomClaim>(reader.GetString());
                claims[CustomClaimName] = _customClaim;
                reader.Read();
            }
            else
            {
                // Call base implementation to handle other claims known to IdentityModel.
                base.ReadPayloadValue(ref reader, claims);
            }
        }
    }

    public class CustomClaim
    {
        public CustomClaim()
        {
        }

        public string CustomClaimValue { get; set; }
    }
}
