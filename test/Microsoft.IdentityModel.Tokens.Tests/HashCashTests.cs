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
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Reflection;
using Microsoft.IdentityModel.TestUtils;
using Xunit;
using System.Diagnostics;

namespace Microsoft.IdentityModel.Tokens.Tests
{
    public class HashCacheTests
    {
        [Fact]
        public void Contains()
        {
            TestUtilities.WriteHeader($"{this}.Contains");
            var context = new CompareContext($"{this}.Contains");
            var cache = new HashCache<int?, string>(10);
            cache.SetValue(1, "one");
            if (!cache.Contains(1))
                context.AddDiff($"HashCache should contain the key value pair [1, 'one'], but the {CurrentMethod} method returned false.");

            cache.TryRemove(1, out _);
            if (cache.Contains(1))
                context.AddDiff($"The key value pair [1, 'one'] should have been removed from the cache, but the {CurrentMethod} method returned true.");

            try
            {
                cache.Contains(null);
                context.AddDiff($"The parameter passed into the {CurrentMethod} method was null, but no exception was thrown.");
            }
            catch (Exception ex)
            {
                if (!ex.GetType().Equals(typeof(ArgumentNullException)))
                    context.AddDiff($"{CurrentMethod}: The exception type thrown by Contains(null) was not of type ArgumentNullException.");
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        [Fact]
        public void SetValue()
        {
            TestUtilities.WriteHeader($"{this}.SetValue");
            var context = new CompareContext($"{this}.SetValue");
            var cache = new HashCache<int?, string>(1);
            Assert.Throws<ArgumentNullException>(() => cache.SetValue(1, null));

            cache.SetValue(1, "one");
            if (!cache.Contains(1))
                context.AddDiff($"{CurrentMethod}: The key value pair [1, 'one'] should have been added to the cache, but the Contains() method returned false.");

            cache.SetValue(1, "one");
            if (!cache.Contains(1))
                context.AddDiff($"{CurrentMethod}: The key value pair [1, 'one'] should have been added to the cache, but the Contains() method returned false.");

            // The LRU item should be removed, allowing this value to be added even though the cache is full.
            cache.SetValue(2, "two");
            if (!cache.Contains(2))
                context.AddDiff($"{CurrentMethod}: The key value pair [2, 'two'] should have been added to the cache, but the Contains() method returned false.");

            try
            {
                cache.SetValue(null, "three");
                context.AddDiff($"The first parameter passed into the {CurrentMethod} method was null, but no exception was thrown.");
            }
            catch (Exception ex)
            {
                if (!ex.GetType().Equals(typeof(ArgumentNullException)))
                    context.AddDiff($"The exception type thrown by {CurrentMethod} was not of type ArgumentNullException.");
            }

            try
            {
                cache.SetValue(3, null);
                context.AddDiff($"The second parameter passed into the {CurrentMethod} method was null, but no exception was thrown.");
            }
            catch (Exception ex)
            {
                if (!ex.GetType().Equals(typeof(ArgumentNullException)))
                    context.AddDiff($"The exception type thrown by {CurrentMethod} was not of type ArgumentNullException.");
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        [Fact]
        public void TryGetValue()
        {
            TestUtilities.WriteHeader($"{this}.TryGetValue");
            var context = new CompareContext($"{this}.TryGetValue");
            var cache = new HashCache<int?, string>(2);
            cache.SetValue(1, "one");

            if (!cache.TryGetValue(1, out var value))
            {
                context.AddDiff($"The key value pair [1, 'one'] should be in the cache, but the {CurrentMethod} method returned false.");
                if (!value.Equals("one"))
                    context.AddDiff($"{CurrentMethod}: The corresponding value for key '1' should be 'one' but was '{value}'.");
            }

            if (cache.TryGetValue(2, out _))
                context.AddDiff($"A key value pair with a key of '2' was never added to the cache, but the {CurrentMethod} method returned true.");

            try
            {
                cache.TryGetValue(null, out _);
                context.AddDiff($"The first parameter passed into the {CurrentMethod} method was null, but no exception was thrown.");
            }
            catch (Exception ex)
            {
                if (!ex.GetType().Equals(typeof(ArgumentNullException)))
                    context.AddDiff($"The exception type thrown by {CurrentMethod} method was not of type ArgumentNullException.");
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        [Fact]
        public void TryRemove()
        {
            TestUtilities.WriteHeader($"{this}.RemoveValue");
            var context = new CompareContext($"{this}.RemoveValue");
            var cache = new HashCache<int?, string>(1);

            cache.SetValue(1, "one");

            if (!cache.TryRemove(1, out _))
                context.AddDiff($"The key value pair [1, 'one'] should have been removed from the cache, but the {CurrentMethod} method returned false.");

            if (cache.TryRemove(2, out _))
                context.AddDiff($"The key value pair [2, 'two'] was never added to the cache, but the {CurrentMethod} method returned true.");

            try
            {
                cache.TryRemove(null, out _);
                context.AddDiff("The first parameter passed into the TryRemove() method was null, but no exception was thrown.");
            }
            catch (Exception ex)
            {
                if (!ex.GetType().Equals(typeof(ArgumentNullException)))
                    context.AddDiff($"The exception type thrown by {CurrentMethod} was not of type ArgumentNullException.");
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        [Fact]
        public void CacheOverflowTestMultithreaded()
        {
            int cacheCapacity = 100;
            int testSize = 10 * cacheCapacity;

            TestUtilities.WriteHeader($"{this}.CacheOverflowTestMultithreaded");
            var context = new CompareContext($"{this}.CacheOverflowTestMultithreaded");
            var cache = new HashCache<int, string>(cacheCapacity);

            List<Task> taskList = new List<Task>();

            for (int i = 0; i < testSize; i++)
            {
                taskList.Add(Task.Factory.StartNew(() =>
                {
                    cache.SetValue(i, i.ToString());
                }));
            }

            Task.WaitAll(taskList.ToArray());

            // wait until the cache compaction is complete
            cache.WaitForProcessing();

            // Cache size should be less than the capacity (somewhere between 800 - 1000 items).
            if (cache.Count > cacheCapacity)
                context.AddDiff("Cache size is greater than the max!");

            TestUtilities.AssertFailIfErrors(context);
        }

        [Fact]
        public void CacheOverflowTestSequential()
        {
            int cacheCapacity = 100;
            int testSize = 10 * cacheCapacity;

            TestUtilities.WriteHeader($"{this}.CacheOverflowTestSequential");
            var context = new CompareContext($"{this}.CacheOverflowTestSequential");
            var cache = new HashCache<int, string>(cacheCapacity);

            for (int i = 0; i < 100000; i++)
            {
                cache.SetValue(i, i.ToString());
            }

            // wait until the cache compaction is complete
            cache.WaitForProcessing();

            // Cache size should be less than the capacity (somewhere between 800-1000 items).
            if (cache.Count > cacheCapacity)
                context.AddDiff("Cache size is greater than the max!");

            TestUtilities.AssertFailIfErrors(context);
        }

        /// <summary>
        /// Gets the name of the current method.
        /// </summary>
        private string CurrentMethod
        {
            get
            {
                var methodInfo = new StackTrace().GetFrame(1).GetMethod();
                return $"{methodInfo.DeclaringType.Name}.{methodInfo.Name}()";
            }
        }
    }
}
