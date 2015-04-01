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
using System.Globalization;
using System.IO;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Logging;

namespace Microsoft.IdentityModel.Protocols
{
    // Works for local files, http https
    public class GenericDocumentRetriever : IDocumentRetriever
    {
        public async Task<string> GetDocumentAsync(string address, CancellationToken cancel)
        {
            if (string.IsNullOrWhiteSpace(address))
            {
                LogHelper.LogError(string.Format(CultureInfo.InvariantCulture, ErrorMessages.IDX10000, GetType() + ": address"), typeof(ArgumentNullException));
            }

            try
            {
                using (HttpClient client = new HttpClient())
                {
                    IdentityModelEventSource.Logger.WriteVerbose("GenericDocumentRetriever.GetDocumentAsync: Obtaining information from metadata endpoint: " + address);
                    using (CancellationTokenRegistration registration = cancel.Register(() => client.CancelPendingRequests()))
                    {
                        return await client.GetStringAsync(address).ConfigureAwait(false);
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
                    LogHelper.LogError("Unable to get document from: " + address, typeof(IOException), ex);
                    return null;
                }
            }
        }
    }
}
