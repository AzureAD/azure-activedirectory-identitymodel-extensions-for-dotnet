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

using System.Threading;
using System.Threading.Tasks;

namespace Microsoft.IdentityModel.Protocols
{
    /// <summary>
    /// IConfigurationManager
    /// </summary>
    /// <typeparam name="T">TODO</typeparam>
    public interface IConfigurationManager<T>
    {
        /// <summary>
        /// Retrieve the current configuration, refreshing and/or caching as needed.
        /// This should throw if the configuration cannot be retrieved, instead of returning null.
        /// </summary>
        /// <param name="cancel"></param>
        /// <returns></returns>
        Task<T> GetConfigurationAsync(CancellationToken cancel);

        /// <summary>
        /// Indicate that the configuration may be stale (as indicated by failing to process incoming tokens).
        /// </summary>
        void RequestRefresh();
    }
}
