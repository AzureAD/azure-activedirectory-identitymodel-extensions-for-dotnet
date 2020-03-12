// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.IdentityModel.Tokens;
using System.Threading.Tasks;

namespace System.ServiceModel.Caching
{
    /// <summary>
    /// Defines methods to enable caching security tokens.
    /// </summary>
    /// <typeparam name="TKey">The type to be used as the key to lookup security tokens.</typeparam>
    public interface ISecurityTokenCache<TKey>
    {
        /// <summary>
        /// Store a security token in the cache with a particular key.
        /// </summary>
        /// <param name="key">The key to use for the provided security token.</param>
        /// <param name="securityToken">The security token to store.</param>
        void CacheSecurityToken(TKey key, SecurityToken securityToken);

        /// <summary>
        /// Asynchronously store a security token in the cache with a particular key.
        /// </summary>
        /// <param name="tokenKey">The key to use for the provided security token.</param>
        /// <param name="securityToken">The security token to store.</param>
        Task CacheSecurityTokenAsync(TKey tokenKey, SecurityToken securityToken);

        /// <summary>
        /// Retrieve a security token from the cache.
        /// </summary>
        /// <param name="tokenKey">The key corresponding to the security token to return.</param>
        /// <returns>The security token corresponding to the key or null if the key is not present in the cache.</returns>
        SecurityToken GetSecurityToken(TKey tokenKey);

        /// <summary>
        /// Asynchronously retrieve a security token from the cache.
        /// </summary>
        /// <param name="tokenKey">The key corresponding to the security token to return.</param>
        /// <returns>The security token corresponding to the key or null if the key is not present in the cache.</returns>
        Task<SecurityToken> GetSecurityTokenAsync(TKey tokenKey);

        /// <summary>
        /// Remove a security token from the cache.
        /// </summary>
        /// <param name="securityToken">The security token to be removed from the cache.</param>
        /// <returns>True if the security token was removed from the cache, otherwise false.</returns>
        bool RemoveSecurityToken(SecurityToken securityToken);

        /// <summary>
        /// Asynchronously remove a security token from the cache.
        /// </summary>
        /// <param name="securityToken">The security token to be removed from the cache.</param>
        /// <returns>True if the security token was removed from the cache, otherwise false.</returns>
        Task<bool> RemoveSecurityTokenAsync(SecurityToken securityToken);

        /// <summary>
        /// Remove a security token from the cache.
        /// </summary>
        /// <param name="tokenKey">The key corresponding to the security token to be removed from the cache.</param>
        /// <returns>True if the security token was removed from the cache, otherwise false.</returns>
        bool RemoveSecurityTokenByKey(TKey tokenKey);

        /// <summary>
        /// Asynchronously remove a security token from the cache.
        /// </summary>
        /// <param name="tokenKey">The key corresponding to the security token to be removed from the cache.</param>
        /// <returns>True if the security token was removed from the cache, otherwise false.</returns>
        Task<bool> RemoveSecurityTokenByKeyAsync(TKey tokenKey);
    }
}
