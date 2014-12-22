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
using System.IO;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

namespace Microsoft.IdentityModel.Protocols
{
    // Works for local files, http https
    // TODO - brentschmaltz, proper documentation
    public class GenericDocumentRetriever : IDocumentRetriever
    {
        public async Task<string> GetDocumentAsync(string address, CancellationToken cancel)
        {
            if (string.IsNullOrWhiteSpace(address))
            {
                throw new ArgumentNullException("address");
            }

            try
            {
                using (HttpClient client = new HttpClient())
                {
                    using (CancellationTokenRegistration registration = cancel.Register(() => client.CancelPendingRequests()))
                    {
                        return await client.GetStringAsync(address);
                    }
                }
            }
            catch (Exception ex)
            {
                if (File.Exists(address))
                {
                    return File.ReadAllText(address);
                }
                else
                {
                    // TODO - brentschmaltz, loc
                    throw new IOException("Unable to get document from: " + address, ex);
                }
            }
        }
    }
}
