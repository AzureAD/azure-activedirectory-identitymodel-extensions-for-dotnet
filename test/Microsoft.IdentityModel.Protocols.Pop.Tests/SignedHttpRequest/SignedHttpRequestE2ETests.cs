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

using Microsoft.IdentityModel.Tokens;
using System;
using Xunit;
using System.Collections.Generic;
using System.Threading;
using System.Net.Http;
using System.Net.Http.Headers;
using Microsoft.IdentityModel.Protocols.Pop.SignedHttpRequest;
using Microsoft.IdentityModel.TestUtils;

namespace Microsoft.IdentityModel.Protocols.Pop.Tests.SignedHttpRequest
{
    public class SignedHttpRequestE2ETests
    {
        [Fact]
        public async void RoundtripTest()
        {
            var popHandler = new SignedHttpRequestHandler();

            /* set the HttpRequestData via HttpRequestMessage
            var requestMessage = new HttpRequestMessage();
            requestMessage.RequestUri = new Uri("https://www.contoso.com:443/it/requests?b=bar&a=foo&c=duck");
            requestMessage.Method = HttpMethod.Get;
            requestMessage.Headers.Add("Etag", "742-3u8f34-3r2nvv3");
            requestMessage.Content = new ByteArrayContent(Guid.NewGuid().ToByteArray());
            requestMessage.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
            var httpRequestData = await requestMessage.ToHttpRequestDataAsync().ConfigureAwait(false);
            */

            //or set up http request data directly
            var httpRequestData = new HttpRequestData()
            {
                Method = "GET",
                Uri = new Uri("https://www.contoso.com:443/it/requests?b=bar&a=foo&c=duck"),
                Body = Guid.NewGuid().ToByteArray(),
                Headers = new Dictionary<string, IEnumerable<string>>
                {
                    { "Content-Type", new List<string> { "application/json" } },
                    { "Etag", new List<string> { "742-3u8f34-3r2nvv3" } },
                }
            };


            // adjust the creationPolicy
            var creationPolicy = new SignedHttpRequestCreationPolicy()
            {
                CreateTs = true,
                CreateM = true,
                CreateP = true,
                CreateU = true,
                CreateH = true,
                CreateB = true,
                CreateQ = true,
            };

            // adjust the validationPolicy
            var validationPolicy = new SignedHttpRequestValidationPolicy()
            {
                ValidateTs = true,
                ValidateM = true,
                ValidateP = true,
                ValidateU = true,
                ValidateH = true,
                ValidateB = true,
                ValidateQ = true,
            };

            var tokenValidationParameters = new TokenValidationParameters()
            {
                ValidateAudience = false,
                ValidateIssuer = false,
                IssuerSigningKey = SignedHttpRequestTestUtils.DefaultSigningCredentials.Key
            };

            try
            {
                var signedHttpRequestCreationData = new SignedHttpRequestCreationData(SignedHttpRequestTestUtils.DefaultEncodedAccessToken, httpRequestData, SignedHttpRequestTestUtils.DefaultSigningCredentials, creationPolicy);
                var signedHttpRequest = await popHandler.CreateSignedHttpRequestAsync(signedHttpRequestCreationData, CancellationToken.None).ConfigureAwait(false);

                var signedHttpRequestValiationData = new SignedHttpRequestValidationData(signedHttpRequest, httpRequestData, tokenValidationParameters, validationPolicy);
                var result = await popHandler.ValidateSignedHttpRequestAsync(signedHttpRequestValiationData, CancellationToken.None).ConfigureAwait(false);

                //4.1.
                var signedHttpRequestHeader = PopUtilities.CreateSignedHttpRequestHeader(result.SignedHttpRequest);
            }
            catch (PopException e)
            {
                // handle the exception
                throw e;
            }
            catch (Exception ex)
            {
                // handle the exception
                throw ex;
            }
        }
    }
}
