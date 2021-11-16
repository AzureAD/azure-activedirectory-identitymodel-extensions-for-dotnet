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

namespace Microsoft.IdentityModel.Tokens
{
    /// <summary>
    /// The provider interface.
    /// </summary>
    /// <typeparam name="TKey">The key of a provider, used for cache operations.</typeparam>
    /// <typeparam name="TValue">The value of a provider.</typeparam>
    internal interface IProviderCache<TKey, TValue>
    {
        /// <summary>
        /// Determines whether the cache contains the specified key.
        /// </summary>
        /// <param name="key">The key to check.</param>
        /// <returns>true if the key is found; otherwise, false.</returns>
        public bool Contains(TKey key);

        /// <summary>
        /// Gets the value (CacheItem.Value) of the cached item from the hash.
        /// </summary>
        /// <param name="key">The key of the value to get.</param>
        /// <param name="value">The object that has the specified key, or the default value of the type if the not found.</param>
        /// <returns>true if the key was found, otherwise, false.</returns>
        public bool TryGetValue(TKey key, out TValue value);

        /// <summary>
        /// Removes a particular key from the cache.
        /// </summary>
        /// <param name="key">The key of the item to remove.</param>
        /// <param name="value">The object removed from the cache, or the default value of the TValue type if key does not exist.</param>
        /// <returns>true if the object was removed successfully; false otherwise.</returns>
        public bool TryRemove(TKey key, out TValue value);

        /// <summary>
        /// Adds or updates the value associated with key.
        /// </summary>
        /// <param name="key">The key of the value.</param>
        /// <param name="value">The new value replacing the existing value.</param>
        public void SetValue(TKey key, TValue value);

        /// <summary>
        /// Adds or updates the value associated with key.
        /// </summary>
        /// <param name="key">The key of the value.</param>
        /// <param name="value">The new value replacing the existing value.</param>
        /// <param name="expirationTime">The expiration time for the item.</param>
        /// <exception cref="ArgumentNullException"><paramref name="key"/> is null.</exception>
        /// <exception cref="ArgumentNullException"><paramref name="value"/> is null.</exception>
        /// <returns>true if the item is successfully added to the cache.</returns>
        public bool SetValue(TKey key, TValue value, DateTime expirationTime);
   }
}
