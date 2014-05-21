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

using System;
using System.Threading;
using System.Threading.Tasks;

namespace Microsoft.IdentityModel.Protocols
{
    public class ConstantMetadataManager<T> : IMetadataManager<T>
    {
        private T _metadata;

        public ConstantMetadataManager(T metadata)
        {
            if (metadata == null)
            {
                throw new ArgumentNullException("metadata");
            }
            _metadata = metadata;
        }

        public Task<T> GetMetadataAsync(CancellationToken cancel)
        {
            return Task.FromResult(_metadata);
        }

        public void RequestRefresh()
        {
        }
    }
}
