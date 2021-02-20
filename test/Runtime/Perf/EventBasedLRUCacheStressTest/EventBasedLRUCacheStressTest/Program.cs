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
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics.Tracing;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Tokens;

namespace EventBasedLRUValueCacheStressTest
{
    class Program
    {
        static void Main(string[] args)
        {
            CacheOverflowTestMultithreaded();
            //CacheOverflowTestSequential();
        }

        static long CacheGetTest(bool useQueue, int processingDelay = 0)
        {
            var cache = new EventBasedValueLRUCache<int, string>(1000);
            cache.UseQueue = useQueue;
            cache.ProcessingDelay = processingDelay;

            for (int i = 0; i < 1000; i++)
                cache.SetValue(i, i.ToString());

            List<Task> taskList = new List<Task>();
            ConcurrentQueue<string> items = new ConcurrentQueue<string>();

            var watch = new System.Diagnostics.Stopwatch();

            watch.Start();

            for (int i = 0; i < 1000; i++)
            {
                taskList.Add(Task.Factory.StartNew(() =>
                {
                    cache.TryGetValue(i, out var value);
                }));
            }


            Task.WaitAll(taskList.ToArray());

            watch.Stop();

            Console.WriteLine($"Execution Time: {watch.ElapsedMilliseconds} ms");

            return watch.ElapsedMilliseconds;

         
        }

        static void CacheOverflowTestMultithreaded()
        {
            //var cache = new EventBasedValueLRUCache<int, string>(1000);
            var cache = new EventBasedReferenceLRUCache<int, string>(1000);

            List<Task> taskList = new List<Task>();

            for (int i = 0; i < 100000; i++)
            {
                taskList.Add(Task.Factory.StartNew(() =>
                {
                    cache.SetValue(i, i.ToString());
                }));
            }

            //for (int i = 0; i < 1000; i++)
            //{
            //    for (int j = 0; j < 100; j++)
            //    {
            //        var rand = new Random().Next();
            //        taskList.Add(Task.Factory.StartNew(() =>
            //        {
            //            cache.SetValue(rand, Guid.NewGuid().ToString());
            //            //cache.SetValue(i, i.ToString());
            //        }));
            //    }
            //}

            Task.WaitAll(taskList.ToArray());
            while (cache.LinkedListValues.Count() != 1000)
            {
                Console.WriteLine(cache.LinkedListValues.Count());
                Thread.Sleep(1000);
            }

            Console.ReadLine();
        }

        static void CacheOverflowTestSequential()
        {
            var cache = new EventBasedValueLRUCache<int, string>(1000);


            for (int i = 0; i < 1000; i++)
            {
                for (int j = 0; j < 1000; j++)
                {
                    cache.SetValue(i, i.ToString());
                }
            }

            while (cache.LinkedListValues.Count() != 1000)
            {
                Console.WriteLine(cache.LinkedListValues.Count());
                Thread.Sleep(1000);
            }

            Console.ReadLine();
        }
    }
}
