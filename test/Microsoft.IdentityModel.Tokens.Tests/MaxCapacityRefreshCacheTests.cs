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

using Microsoft.IdentityModel.TestUtils;
using Xunit;

namespace Microsoft.IdentityModel.Tokens.Tests
{
    public class MaxCapacityRefreshCacheTests
    {
        [Fact]
        public void CacheRefresh()
        {
            var context = new CompareContext();
            var cache = new MaxCapacityRefreshCache<string, string>(2);
            cache.SetValue("1", "1");
            cache.SetValue("2", "2");
            if (!cache.Contains("1"))
                context.AddDiff("Cache is missing the '1' key.");
            if (!cache.Contains("2"))
                context.AddDiff("Cache is missing the '2' key.");

            cache.SetValue("3", "3");
            if (cache.Contains("1"))
                context.AddDiff("Cache has been cleared and should not contain the '1' key.");
            if (cache.Contains("2"))
                context.AddDiff("Cache has been cleared and should not contain the '2' key.");
            if (!cache.Contains("3"))
                context.AddDiff("'3' key should have been added to the cache after it was cleared.");

            TestUtilities.AssertFailIfErrors(context);
        }
    }
}
