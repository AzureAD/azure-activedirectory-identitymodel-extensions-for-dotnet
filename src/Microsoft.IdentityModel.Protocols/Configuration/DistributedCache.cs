using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using System.Web;
using Microsoft.IdentityModel.Tokens.Json;

namespace Microsoft.IdentityModel.Protocols.Configuration
{
    /// <summary>
    /// </summary>
    class DistributedCache : IDistributedCache
    {
        private readonly Dictionary<string, string> _storage = new();

        public Task<string> GetStringAsync(string key, CancellationToken cancellationToken)
        {
            if (_storage.TryGetValue(key, out var value))
            {
                return Task.FromResult(value);
            }

            return Task.FromResult<string>(null);
        }

        public Task SetStringAsync(string key, string value, CancellationToken cancellationToken)
        {
            _storage[key] = value;
            return Task.CompletedTask;
        }
    }
}
