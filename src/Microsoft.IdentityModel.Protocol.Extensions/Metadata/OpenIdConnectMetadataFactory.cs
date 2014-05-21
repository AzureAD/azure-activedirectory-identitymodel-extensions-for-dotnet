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
    public static class OpenIdConnectMetadataFactory
    {
        public static Task<OpenIdConnectMetadata> GetMetadataAsync(string metadataAddress, CancellationToken cancel)
        {
            return new OpenIdConnectMetadataReader().ReadMetadataAysnc(new WebClientDocumentRetriever(), metadataAddress, cancel);
        }

        public static Task<OpenIdConnectMetadata> GetMetadataFromHttpAsync(string metadataAddress, HttpClient httpClient, CancellationToken cancel)
        {
            return new OpenIdConnectMetadataReader().ReadMetadataAysnc(new HttpDocumentRetriever(httpClient), metadataAddress, cancel);
        }

        public static Task<OpenIdConnectMetadata> GetMetadataFromFileAsync(string metadataAddress, CancellationToken cancel)
        {
            return new OpenIdConnectMetadataReader().ReadMetadataAysnc(new FileDocumentRetriever(), metadataAddress, cancel);
        }

        public static IMetadataManager<OpenIdConnectMetadata> CreateMetadataManager(OpenIdConnectMetadata metadata)
        {
            return new ConstantMetadataManager<OpenIdConnectMetadata>(metadata);
        }

        public static RefreshingMetadataManager<OpenIdConnectMetadata> CreateRefreshingMetadataManager(string metadataAddress)
        {
            return new RefreshingMetadataManager<OpenIdConnectMetadata>(metadataAddress, new WebClientDocumentRetriever(), new OpenIdConnectMetadataReader());
        }

        public static RefreshingMetadataManager<OpenIdConnectMetadata> CreateRefreshingHttpMetadataManager(string metadataAddress, HttpClient httpClient)
        {
            return new RefreshingMetadataManager<OpenIdConnectMetadata>(metadataAddress, new HttpDocumentRetriever(httpClient), new OpenIdConnectMetadataReader());
        }

        public static RefreshingMetadataManager<OpenIdConnectMetadata> CreateRefreshingFileMetadataManager(string metadataAddress)
        {
            return new RefreshingMetadataManager<OpenIdConnectMetadata>(metadataAddress, new FileDocumentRetriever(), new OpenIdConnectMetadataReader());
        }
    }
}
