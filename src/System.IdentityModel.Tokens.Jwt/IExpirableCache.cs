//-----------------------------------------------------------------------
// Copyright (c) Microsoft Open Technologies, Inc.
// All Rights Reserved
// Apache License 2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// 
// http://www.apache.org/licenses/LICENSE-2.0
// 
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//-----------------------------------------------------------------------

namespace System.IdentityModel.Tokens
{
    /// <summary>
    /// Interface
    /// </summary>
    public interface IExpirableCache
    {
        /// <summary>
        /// Try to add an item to the cache.
        /// </summary>
        /// <param name="item">item to add.</param>
        /// <param name="expiresOn"></param>
        /// <returns>true is item was successfully added, false otherwise.</returns>
        bool TryAdd(string item, DateTime expiresOn);

        /// <summary>
        /// Try to find an item.
        /// </summary>
        /// <param name="item"></param>
        /// <returns>true if found, false otherwise.</returns>
        bool TryFind(string item);
    }
}
