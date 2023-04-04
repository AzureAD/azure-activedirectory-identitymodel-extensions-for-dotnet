// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using Microsoft.IdentityModel.Protocols.Configuration;
using Microsoft.IdentityModel.Tokens.Configuration;
using Xunit;

namespace Microsoft.IdentityModel.Protocols.Tests
{
    public class LastKnownGoodConfigurationCacheOptionsTests
    {
        [Fact]
        public void ImplicitConversionToLKGConfigurationCacheOptions()
        {
            LastKnownGoodConfigurationCacheOptions options = new LastKnownGoodConfigurationCacheOptions
            {
                LastKnownGoodConfigurationSizeLimit = 999
            };

            LKGConfigurationCacheOptions implicitlyConvertedOptions = options;
            Assert.Equal(options.LastKnownGoodConfigurationSizeLimit, implicitlyConvertedOptions.LastKnownGoodConfigurationSizeLimit);
            Assert.True(Object.ReferenceEquals(options.BaseConfigurationComparer, implicitlyConvertedOptions.BaseConfigurationComparer));
        }
    }
}
