// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections.Concurrent;
using BenchmarkDotNet.Attributes;

namespace Microsoft.IdentityModel.Benchmarks
{
    // dotnet run -c release -f net8.0 --filter Microsoft.IdentityModel.Benchmarks.ExpiredCheck*

    public class ExpiredCheck
    {
        private ConcurrentDictionary<int, DateTime> _map1;
        private ConcurrentDictionary<int, DateTime> _map2;

        [GlobalSetup]
        public void Setup()
        {
            _map1 = new ConcurrentDictionary<int, DateTime>();
            _map2 = new ConcurrentDictionary<int, DateTime>();

            DateTime now = DateTime.UtcNow;
            for (int i = 0; i < 100000; i++)
            {
                _map1.TryAdd(i, now);
                _map2.TryAdd(i, now);
            }
        }

        [Benchmark]
        public void RemoveUsingDateTimeUtcNow()
        {
            foreach (var entry in _map1)
            {
                if (entry.Value < DateTime.UtcNow)
                {
                    _map1.TryRemove(entry.Key, out _);
                }
            }
        }

        [Benchmark]
        public void RemoveUsingDateTimeVariable()
        {
            DateTime now = DateTime.UtcNow;
            foreach (var entry in _map2)
            {
                if (entry.Value < now)
                {
                    _map2.TryRemove(entry.Key, out _);
                }
                
            }
        }
    }
}
