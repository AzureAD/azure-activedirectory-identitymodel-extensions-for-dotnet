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
// all copies or substantial portions of the Software.CryptoProviderCacheOptions
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
using System.Linq;
using System.Threading;
using Microsoft.IdentityModel.TestUtils;
using Xunit;

namespace Microsoft.IdentityModel.Tokens.Tests
{
    public class EventBasedLRUCacheTests
    {
        [Fact]
        public void Contains()
        {
            TestUtilities.WriteHeader($"{this}.Contains");
            var context = new CompareContext($"{this}.Contains");
            var cache = new EventBasedLRUCache<int?, string>(10);

            cache.SetValue(1, "one");
            if (!cache.Contains(1))
                context.AddDiff("Cache should contain the key value pair {1, 'one'}, but the Contains() method returned false.");

            cache.TryRemove(1, out _);
            if(cache.Contains(1))
                context.AddDiff("The key value pair {1, 'one'} should have been removed from the cache, but the Contains() method returned true.");

            try
            {
                cache.Contains(null);
                context.AddDiff("The parameter passed into the Contains() method was null, but no exception was thrown.");
            }
            catch (Exception ex)
            {
                if (!ex.GetType().Equals(typeof(ArgumentNullException)))
                    context.AddDiff("The exception type thrown by Contains(null) was not of type ArgumentNullException.");
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        [Fact]
        public void RemoveExpiredValues()
        {
            TestUtilities.WriteHeader($"{this}.RemoveExpiredValues");
            var context = new CompareContext($"{this}.RemoveExpiredValues");
            var cache = new EventBasedLRUCache<int, string>(10);

            for (int i = 0; i <= 10; i++)
            {
                // Only even values should expire.
                if (i % 2 == 0)
                    cache.SetValue(i, i.ToString(), DateTime.UtcNow + TimeSpan.FromSeconds(5));
                else
                    cache.SetValue(i, i.ToString());
            }

            Thread.Sleep(5000);
            cache.RemoveExpiredValues();

            for (int i = 0; i <= 10; i++)
            {
                // Only even values should expire.
                if (i % 2 == 0)
                {
                    if (cache.Contains(i))
                        context.AddDiff("The key value pair {" + i + ", '" + i.ToString() + "'} should have expired and been removed, but the Contains() method returned true.");
                }
                else
                {
                    if (!cache.Contains(i))
                        context.AddDiff("The key value pair {" + i + ", '" + i.ToString() + "'} should remain in the cache, but the Contains() method returned false.");
                }
            }
            TestUtilities.AssertFailIfErrors(context);
        }

        [Fact]
        public void MaintainLRUOrder()
        {
            TestUtilities.WriteHeader($"{this}.MaintainLRUOrder");
            var context = new CompareContext($"{this}.MaintainLRUOrder");
            var cache = new EventBasedLRUCache<int, string>(10);

            for (int i = 0; i <= 100; i++)
            {
                cache.SetValue(i, Guid.NewGuid().ToString());

                // print the value of the list every 100 items
                if (i % 10 == 0 && i != 0)
                {
                    // wait for the cache events to process
                    Thread.Sleep(2000);

                    if (cache.LinkedListValues().Intersect(cache.MapValues()).Count() != 10)
                        context.AddDiff("Values in the map and corresponding linked list do not match up.");
                }

            }

            // Values 91-100 should now be in the cache, with 100 being first in the list and 91 being last.
            if (cache.LinkedListValues().First.Value.Key != 100)
                context.AddDiff("100 should be the first value in the linked list, but instead it was : " + cache.LinkedListValues().First.Value.Key);

            if (cache.LinkedListValues().Last.Value.Key != 91)
                context.AddDiff("91 should be the last value in the linked list, but instead it was : " + cache.LinkedListValues().Last.Value.Key);

            cache.SetValue(101, Guid.NewGuid().ToString());

            // wait for the cache events to process
            Thread.Sleep(1000);

            if (cache.LinkedListValues().First.Value.Key != 101)
                context.AddDiff("101 should be the first value in the linked list, but instead it was : " + cache.LinkedListValues().First.Value.Key);

            if (cache.LinkedListValues().Last.Value.Key != 92)
                context.AddDiff("92 should be the first value in the linked list, but instead it was : " + cache.LinkedListValues().Last.Value.Key);

            TestUtilities.AssertFailIfErrors(context);
        }
    }
}
