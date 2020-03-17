// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.Threading.Tasks;

namespace System.ServiceModel.Caching
{
    /// <summary>
    /// Defines methods to enable caching responses from a security token issuer.
    /// </summary>
    /// <typeparam name="TKey">The type to be used as the key to lookup security token responses.</typeparam>
    /// <typeparam name="TValue">The type of response to cache.</typeparam>
    public interface ISecurityTokenResponseCache<TKey, TValue> where TValue: class
    {
        /// <summary>
        /// Store a security token response in the cache with a particular key.
        /// </summary>
        /// <param name="key">The key to use for the provided response.</param>
        /// <param name="response">The security token response to store.</param>
        void CacheSecurityTokenResponse(TKey key, TValue response);

        /// <summary>
        /// Asynchronously store a security token response in the cache with a particular key.
        /// </summary>
        /// <param name="key">The key to use for the provided response.</param>
        /// <param name="response">The security token response to store.</param>
        Task CacheSecurityTokenResponseAsync(TKey key, TValue response);

        /// <summary>
        /// Retrieve a security token response from the cache.
        /// </summary>
        /// <param name="key">The key corresponding to the security token response to return.</param>
        /// <returns>The security token response corresponding to the key or null if the key is not present in the cache.</returns>
        TValue GetSecurityTokenResponse(TKey key);

        /// <summary>
        /// Asynchronously retrieve a security token response from the cache.
        /// </summary>
        /// <param name="key">The key corresponding to the security token response to return.</param>
        /// <returns>The security token response corresponding to the key or null if the key is not present in the cache.</returns>
        Task<TValue> GetSecurityTokenResponseAsync(TKey key);

        /// <summary>
        /// Remove a security token response from the cache.
        /// </summary>
        /// <param name="response">The security token response to be removed from the cache.</param>
        /// <returns>True if the response was removed from the cache, otherwise false.</returns>
        bool RemoveSecurityTokenResponse(TValue response);

        /// <summary>
        /// Asynchronously remove a security token response from the cache.
        /// </summary>
        /// <param name="response">The security token response to be removed from the cache.</param>
        /// <returns>True if the response was removed from the cache, otherwise false.</returns>
        Task<bool> RemoveSecurityTokenResponseAsync(TValue response);

        /// <summary>
        /// Remove a security token response from the cache.
        /// </summary>
        /// <param name="key">The key corresponding to the security token response to be removed from the cache.</param>
        /// <returns>True if the response was removed from the cache, otherwise false.</returns>
        bool RemoveSecurityTokenResponseByKey(TKey key);

        /// <summary>
        /// Asynchronously remove a security token response from the cache.
        /// </summary>
        /// <param name="key">The key corresponding to the security token response to be removed from the cache.</param>
        /// <returns>True if the response was removed from the cache, otherwise false.</returns>
        Task<bool> RemoveSecurityTokenResponseByKeyAsync(TKey key);
    }
}
