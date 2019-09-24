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
using System.Security.Cryptography;
using System.Collections.Generic;
using System.Threading;
using System.Net.Http;
using System.Net.Http.Headers;
using Microsoft.IdentityModel.Protocols.PoP.SignedHttpRequest;

namespace Microsoft.IdentityModel.Protocols.PoP.Tests
{
    public class PopTests
    {
        [Fact]
        public async void MsalUsageSample()
        {
            var popHandler = new SignedHttpRequestHandler();

            string accessTokenWithCnfClaim = "eyJhbGciOiJSUzI1NiIsImtpZCI6IlJzYVNlY3VyaXR5S2V5XzIwNDgiLCJ0eXAiOiJKV1QifQ.eyJhcHBpZCI6ImJiYmJiYmJiLWViZjUtNGI3MC04ZWIwLWZkMjYzMDNiNmE1ZiIsImFwcGlkYWNyIjoiMiIsImF1ZCI6IjkxOTE5NmY2LTM4ZmQtNDZmMy04Njg2LWE0OWUyOTQ0YjI3NyIsImV4cCI6MTU3Nzg2OTI2MSwiaWF0IjoxNDgzMjYxMjYxLCJpc3MiOiJodHRwczovL3N0cy53aW5kb3dzLm5ldC9hZGQyOTQ4OS03MjY5LTQxZjQtODg0MS1iNjNjOTU1NjQ0MjEvIiwibmJmIjoxNDgzMjYxMjYxLCJvaWQiOiJkMWFkOWNlNy1iMzIyLTQyMjEtYWI3NC0xZTEwMTFlMWJiY2IiLCJzdWIiOiJNQVM2Y05OallPVUtqRXpLbzViY3NsUHJ6LWhoMXNGUjR1RHlaNkxZQ1gwIiwidGlkIjoiYWRkMjk0ODktNzI2OS00MWY0LTg4NDEtYjYzYzk1NTY0NDIxIiwidmVyIjoiMS4wIiwiY25mIjp7Imp3ayI6eyJrdHkiOiJSU0EiLCJuIjoiNi1GckZrdF9UQnlRX0w1ZDdvci05UFZBb3dwc3d4VWUzZEplWUZUWTBMZ3E3ektJNU9RNVJuU3JJMFQ5eXJmblJ6RTlvT2RkNHptVmo5dHhWTEkteXlTdmluQXUzeVFEUW91MkdhNDJNTF8tSzRKcmQ1Y2xNVVBSR01iWGRWNVJsOXp6QjBzMkpvWkplZHVhNWR3b1F3MEdrUzVaOFlBWEJFelVMcnVwMDZmbkI1bjZ4NXIyeTFDXzhFYnA1Y3lFNEJqczdXNjhyVWx5SWx4MWx6WXZha3hTbmhVeFNzang3dV9tSWR5d3lHZmdpVDN0dzBGc1d2a2lfS1l1ckFQUjFCU01YaEN6elpUa01XS0U4SWFMa2hhdXc1TWR4b2p4eUJWdU5ZLUpfZWxxLUhnSl9kWks2Zzd2TU52WHoyX3ZULVN5a0lrendpRDllU0k5VVdmc2p3IiwiZSI6IkFRQUIiLCJhbGciOiJSUzI1NiIsImtpZCI6IlJzYVNlY3VyaXR5S2V5XzIwNDgifX19.HGPPwvlAzliPRSjXJ1T50y9P_LbytACfG1Jr-rqOQGerozjZ0ivFhhNUB_QMp5rMRMR854Dh7CkFUfvgJza3MKs7--a_FHJueack-6KueDGAtP_5fzUiqoGJB5Qnz0VsLrUCDyzub6hUm0d9R-gJ-mQs_7ybYQMuHDFzC_CG9zs8VpeEVcjOBzflg8ZKppQlfomRJ8v2rhkeZC7l3cjzN_pS1NH_8wOdhzFaC1csDEmq9Cndg5dRwm0IshIOGc6kYQfS2wUXGucfE6S0z3vExXjF1oxESR-G74R6zZFKksh9YBye1TU10CwKK_eeswqgUwH6bxHoX926ITscrX__HA";
            var RsaParameters_2048 = new RSAParameters
            {
                D = Base64UrlEncoder.DecodeBytes("C6EGZYf9U6RI5Z0BBoSlwy_gKumVqRx-dBMuAfPM6KVbwIUuSJKT3ExeL5P0Ky1b4p-j2S3u7Afnvrrj4HgVLnC1ks6rEOc2ne5DYQq8szST9FMutyulcsNUKLOM5cVromALPz3PAqE2OCLChTiQZ5XZ0AiH-KcG-3hKMa-g1MVnGW-SSmm27XQwRtUtFQFfxDuL0E0fyA9O9ZFBV5201ledBaLdDcPBF8cHC53Gm5G6FRX3QVpoewm3yGk28Wze_YvNl8U3hvbxei2Koc_b9wMbFxvHseLQrxvFg_2byE2em8FrxJstxgN7qhMsYcAyw1qGJY-cYX-Ab_1bBCpdcQ"),
                DP = Base64UrlEncoder.DecodeBytes("ErP3OpudePAY3uGFSoF16Sde69PnOra62jDEZGnPx_v3nPNpA5sr-tNc8bQP074yQl5kzSFRjRlstyW0TpBVMP0ocbD8RsN4EKsgJ1jvaSIEoP87OxduGkim49wFA0Qxf_NyrcYUnz6XSidY3lC_pF4JDJXg5bP_x0MUkQCTtQE"),
                DQ = Base64UrlEncoder.DecodeBytes("YbBsthPt15Pshb8rN8omyfy9D7-m4AGcKzqPERWuX8bORNyhQ5M8JtdXcu8UmTez0j188cNMJgkiN07nYLIzNT3Wg822nhtJaoKVwZWnS2ipoFlgrBgmQiKcGU43lfB5e3qVVYUebYY0zRGBM1Fzetd6Yertl5Ae2g2CakQAcPs"),
                Exponent = Base64UrlEncoder.DecodeBytes("AQAB"),
                InverseQ = Base64UrlEncoder.DecodeBytes("lbljWyVY-DD_Zuii2ifAz0jrHTMvN-YS9l_zyYyA_Scnalw23fQf5WIcZibxJJll5H0kNTIk8SCxyPzNShKGKjgpyZHsJBKgL3iAgmnwk6k8zrb_lqa0sd1QWSB-Rqiw7AqVqvNUdnIqhm-v3R8tYrxzAqkUsGcFbQYj4M5_F_4"),
                Modulus = Base64UrlEncoder.DecodeBytes("6-FrFkt_TByQ_L5d7or-9PVAowpswxUe3dJeYFTY0Lgq7zKI5OQ5RnSrI0T9yrfnRzE9oOdd4zmVj9txVLI-yySvinAu3yQDQou2Ga42ML_-K4Jrd5clMUPRGMbXdV5Rl9zzB0s2JoZJedua5dwoQw0GkS5Z8YAXBEzULrup06fnB5n6x5r2y1C_8Ebp5cyE4Bjs7W68rUlyIlx1lzYvakxSnhUxSsjx7u_mIdywyGfgiT3tw0FsWvki_KYurAPR1BSMXhCzzZTkMWKE8IaLkhauw5MdxojxyBVuNY-J_elq-HgJ_dZK6g7vMNvXz2_vT-SykIkzwiD9eSI9UWfsjw"),
                P = Base64UrlEncoder.DecodeBytes("_avCCyuo7hHlqu9Ec6R47ub_Ul_zNiS-xvkkuYwW-4lNnI66A5zMm_BOQVMnaCkBua1OmOgx7e63-jHFvG5lyrhyYEmkA2CS3kMCrI-dx0fvNMLEXInPxd4np_7GUd1_XzPZEkPxBhqf09kqryHMj_uf7UtPcrJNvFY-GNrzlJk"),
                Q = Base64UrlEncoder.DecodeBytes("7gvYRkpqM-SC883KImmy66eLiUrGE6G6_7Y8BS9oD4HhXcZ4rW6JJKuBzm7FlnsVhVGro9M-QQ_GSLaDoxOPQfHQq62ERt-y_lCzSsMeWHbqOMci_pbtvJknpMv4ifsQXKJ4Lnk_AlGr-5r5JR5rUHgPFzCk9dJt69ff3QhzG2c"),
            };
            var RsaSecurityKey_2048 = new RsaSecurityKey(RsaParameters_2048);
            var signingCredentials = new SigningCredentials(RsaSecurityKey_2048, SecurityAlgorithms.RsaSha256, SecurityAlgorithms.Sha256);

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
                HttpMethod = "GET",
                HttpRequestUri = new Uri("https://www.contoso.com:443/it/requests?b=bar&a=foo&c=duck"),
                HttpRequestBody = Guid.NewGuid().ToByteArray(),
                HttpRequestHeaders = new Dictionary<string, IEnumerable<string>>
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
                IssuerSigningKey = RsaSecurityKey_2048
            };

            try
            {
                var signedHttpRequestCreationData = new SignedHttpRequestCreationData(accessTokenWithCnfClaim, httpRequestData, signingCredentials, creationPolicy);
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
