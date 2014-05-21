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

using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

namespace Microsoft.IdentityModel.Protocols
{
    public static class WsFederationMetadataFactory
    {
        public static Task<WsFederationMetadata> GetMetadataAsync(string metadataAddress, CancellationToken cancel)
        {
            return new WsFederationMetadataReader().ReadMetadataAysnc(new WebClientDocumentRetriever(), metadataAddress, cancel);
        }

        public static Task<WsFederationMetadata> GetMetadataFromHttpAsync(string metadataAddress, HttpClient httpClient, CancellationToken cancel)
        {
            return new WsFederationMetadataReader().ReadMetadataAysnc(new HttpDocumentRetriever(httpClient), metadataAddress, cancel);
        }

        public static Task<WsFederationMetadata> GetMetadataFromFileAsync(string metadataAddress, CancellationToken cancel)
        {
            return new WsFederationMetadataReader().ReadMetadataAysnc(new FileDocumentRetriever(), metadataAddress, cancel);
        }

        public static IMetadataManager<WsFederationMetadata> CreateMetadataManager(WsFederationMetadata metadata)
        {
            return new ConstantMetadataManager<WsFederationMetadata>(metadata);
        }
        
        public static RefreshingMetadataManager<WsFederationMetadata> CreateRefreshingMetadataManager(string metadataAddress)
        {
            return new RefreshingMetadataManager<WsFederationMetadata>(metadataAddress, new WebClientDocumentRetriever(), new WsFederationMetadataReader());
        }

        public static RefreshingMetadataManager<WsFederationMetadata> CreateRefreshingHttpMetadataManager(string metadataAddress, HttpClient httpClient)
        {
            return new RefreshingMetadataManager<WsFederationMetadata>(metadataAddress, new HttpDocumentRetriever(httpClient), new WsFederationMetadataReader());
        }

        public static RefreshingMetadataManager<WsFederationMetadata> CreateRefreshingFileMetadataManager(string metadataAddress)
        {
            return new RefreshingMetadataManager<WsFederationMetadata>(metadataAddress, new FileDocumentRetriever(), new WsFederationMetadataReader());
        }
    }
}
