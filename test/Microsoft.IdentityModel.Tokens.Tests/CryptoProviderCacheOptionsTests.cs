//------------------------------------------------------------------------------
//
// Copyright (c) Microsoft Corporation.
// All rights reserved.
//
// This code is licensed under the MIT License.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files(the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and / or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions :
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
//
//------------------------------------------------------------------------------

using System;
using Xunit;

namespace Microsoft.IdentityModel.Tokens.Tests
{
    public class CryptoProviderCacheOptionsTests
    {
        [Fact]
        public void CryptoProviderCacheOptions()
        {
            var options = new CryptoProviderCacheOptions();

            Assert.False(options.RemoveExpiredValues);
            Assert.True(options.CacheType == ProviderCacheType.LRU);

            Assert.Throws<ArgumentOutOfRangeException>(() => options.SizeLimit = 0);
            Assert.Throws<ArgumentOutOfRangeException>(() => options.SizeLimit = -1);
            Assert.Throws<ArgumentOutOfRangeException>(() => options.SizeLimit = 10);
            options.SizeLimit = 11;

            Assert.Throws<ArgumentOutOfRangeException>(() => options.CompactionPercentage = 0.1);
            Assert.Throws<ArgumentOutOfRangeException>(() => options.CompactionPercentage = 0.98);
            options.CompactionPercentage = 0.2;


            // the value should be between 0.5 and 1.0
            Assert.Throws<ArgumentOutOfRangeException>(() => options.MaxCapacityPercentage = 0.3);
            Assert.Throws<ArgumentOutOfRangeException>(() => options.MaxCapacityPercentage = 1.2);
            options.MaxCapacityPercentage = 0.95;

            // the value should be positive
            Assert.Throws<ArgumentOutOfRangeException>(() => options.RemoveExpiredValuesIntervalInSeconds = 0);
            Assert.Throws<ArgumentOutOfRangeException>(() => options.RemoveExpiredValuesIntervalInSeconds = -1);
            options.RemoveExpiredValuesIntervalInSeconds = 300;
        }
    }
}
