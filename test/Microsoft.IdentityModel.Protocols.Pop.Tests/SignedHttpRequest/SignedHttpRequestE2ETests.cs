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

namespace Microsoft.IdentityModel.Protocols.Pop.Tests.SignedHttpRequest
{
    public class SignedHttpRequestE2ETests
    {
        [Fact]
        public async void RoundtripTest()
        {
            var popHandler = new SignedHttpRequestHandler();
            string accessTokenWithCnfClaim = "eyJhbGciOiJSUzI1NiIsImtpZCI6IlJzYVNlY3VyaXR5S2V5XzIwNDgiLCJ0eXAiOiJKV1QifQ.eyJhcHBpZCI6ImJiYmJiYmJiLWViZjUtNGI3MC04ZWIwLWZkMjYzMDNiNmE1ZiIsImFwcGlkYWNyIjoiMiIsImF1ZCI6IjkxOTE5NmY2LTM4ZmQtNDZmMy04Njg2LWE0OWUyOTQ0YjI3NyIsImV4cCI6MTU3Nzg2OTI2MSwiaWF0IjoxNDgzMjYxMjYxLCJpc3MiOiJodHRwczovL3N0cy53aW5kb3dzLm5ldC9hZGQyOTQ4OS03MjY5LTQxZjQtODg0MS1iNjNjOTU1NjQ0MjEvIiwibmJmIjoxNDgzMjYxMjYxLCJvaWQiOiJkMWFkOWNlNy1iMzIyLTQyMjEtYWI3NC0xZTEwMTFlMWJiY2IiLCJzdWIiOiJNQVM2Y05OallPVUtqRXpLbzViY3NsUHJ6LWhoMXNGUjR1RHlaNkxZQ1gwIiwidGlkIjoiYWRkMjk0ODktNzI2OS00MWY0LTg4NDEtYjYzYzk1NTY0NDIxIiwidmVyIjoiMS4wIiwiY25mIjp7Imp3ayI6eyJrdHkiOiJSU0EiLCJuIjoiNi1GckZrdF9UQnlRX0w1ZDdvci05UFZBb3dwc3d4VWUzZEplWUZUWTBMZ3E3ektJNU9RNVJuU3JJMFQ5eXJmblJ6RTlvT2RkNHptVmo5dHhWTEkteXlTdmluQXUzeVFEUW91MkdhNDJNTF8tSzRKcmQ1Y2xNVVBSR01iWGRWNVJsOXp6QjBzMkpvWkplZHVhNWR3b1F3MEdrUzVaOFlBWEJFelVMcnVwMDZmbkI1bjZ4NXIyeTFDXzhFYnA1Y3lFNEJqczdXNjhyVWx5SWx4MWx6WXZha3hTbmhVeFNzang3dV9tSWR5d3lHZmdpVDN0dzBGc1d2a2lfS1l1ckFQUjFCU01YaEN6elpUa01XS0U4SWFMa2hhdXc1TWR4b2p4eUJWdU5ZLUpfZWxxLUhnSl9kWks2Zzd2TU52WHoyX3ZULVN5a0lrendpRDllU0k5VVdmc2p3IiwiZSI6IkFRQUIiLCJhbGciOiJSUzI1NiIsImtpZCI6IlJzYVNlY3VyaXR5S2V5XzIwNDgifX19.HGPPwvlAzliPRSjXJ1T50y9P_LbytACfG1Jr-rqOQGerozjZ0ivFhhNUB_QMp5rMRMR854Dh7CkFUfvgJza3MKs7--a_FHJueack-6KueDGAtP_5fzUiqoGJB5Qnz0VsLrUCDyzub6hUm0d9R-gJ-mQs_7ybYQMuHDFzC_CG9zs8VpeEVcjOBzflg8ZKppQlfomRJ8v2rhkeZC7l3cjzN_pS1NH_8wOdhzFaC1csDEmq9Cndg5dRwm0IshIOGc6kYQfS2wUXGucfE6S0z3vExXjF1oxESR-G74R6zZFKksh9YBye1TU10CwKK_eeswqgUwH6bxHoX926ITscrX__HA";

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
                IssuerSigningKey = SignedHttpRequestTestUtils.SigningCredentials.Key
            };

            try
            {
                var signedHttpRequestCreationData = new SignedHttpRequestCreationData(accessTokenWithCnfClaim, httpRequestData, SignedHttpRequestTestUtils.SigningCredentials, creationPolicy);
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
