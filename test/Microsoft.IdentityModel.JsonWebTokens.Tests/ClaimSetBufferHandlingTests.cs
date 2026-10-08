// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System.Collections.Generic;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace Microsoft.IdentityModel.JsonWebTokens.Tests
{
    public class ClaimSetBufferHandlingTests
    {
        [Fact]
        public void LargeHeaderAndPayload_PooledBufferPath_ClaimsRoundTrip()
        {
            // Arrange
            string largeHeaderValue = new('H', 300);
            string largePayloadValue = new('P', 300);
            var descriptor = new SecurityTokenDescriptor
            {
                AdditionalHeaderClaims = new Dictionary<string, object>
                {
                    ["large-header"] = largeHeaderValue
                },
                Claims = new Dictionary<string, object>
                {
                    ["large-payload"] = largePayloadValue
                }
            };

            // Act
            string encodedToken = new JsonWebTokenHandler().CreateToken(descriptor);
            var token = new JsonWebToken(encodedToken);

            // Assert
            Assert.Equal(largeHeaderValue, token.GetHeaderValue<string>("large-header"));
            Assert.Equal(largePayloadValue, token.GetPayloadValue<string>("large-payload"));
        }
    }
}
