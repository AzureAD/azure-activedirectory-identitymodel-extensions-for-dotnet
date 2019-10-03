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

using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Json;
using Microsoft.IdentityModel.Json.Linq;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.TestUtils;
using Microsoft.IdentityModel.Tokens;
using ClaimTypes = Microsoft.IdentityModel.Protocols.Pop.PopConstants.SignedHttpRequest.ClaimTypes;

namespace Microsoft.IdentityModel.Protocols.Pop.Tests.SignedHttpRequest
{
    public static class SignedHttpRequestTestUtils
    {
        // Default access token. Created using AcessTokenPayload (with CnfJwk) and SignedHttpRequestTestUtils.DefaultSigningCredentials
        internal static string DefaultEncodedAccessToken = "eyJhbGciOiJSUzI1NiIsImtpZCI6IlJzYVNlY3VyaXR5S2V5XzIwNDgiLCJ0eXAiOiJwb3AifQ.eyJlbWFpbCI6IkJvYkBjb250b3NvLmNvbSIsImdpdmVuX25hbWUiOiJCb2IiLCJpc3MiOiJodHRwOi8vRGVmYXVsdC5Jc3N1ZXIuY29tIiwiYXVkIjoiaHR0cDovL0RlZmF1bHQuQXVkaWVuY2UuY29tIiwiaWF0IjoiMTQ4OTc3NTYxNyIsIm5iZiI6IjE0ODk3NzU2MTciLCJleHAiOiIxNjE2MDA2MDE3IiwiY25mIjp7Imp3ayI6eyJrdHkiOiJSU0EiLCJuIjoiNitGckZrdC9UQnlRL0w1ZDdvcis5UFZBb3dwc3d4VWUzZEplWUZUWTBMZ3E3ektJNU9RNVJuU3JJMFQ5eXJmblJ6RTlvT2RkNHptVmo5dHhWTEkreXlTdmluQXUzeVFEUW91MkdhNDJNTC8rSzRKcmQ1Y2xNVVBSR01iWGRWNVJsOXp6QjBzMkpvWkplZHVhNWR3b1F3MEdrUzVaOFlBWEJFelVMcnVwMDZmbkI1bjZ4NXIyeTFDLzhFYnA1Y3lFNEJqczdXNjhyVWx5SWx4MWx6WXZha3hTbmhVeFNzang3dS9tSWR5d3lHZmdpVDN0dzBGc1d2a2kvS1l1ckFQUjFCU01YaEN6elpUa01XS0U4SWFMa2hhdXc1TWR4b2p4eUJWdU5ZK0ovZWxxK0hnSi9kWks2Zzd2TU52WHoyL3ZUK1N5a0lrendpRDllU0k5VVdmc2p3PT0iLCJlIjoiQVFBQiIsImFsZyI6IlJTMjU2Iiwia2lkIjoiUnNhU2VjdXJpdHlLZXlfMjA0OCJ9fX0.DqQ3L67jrUqPK9hNPAM7vnuA-Ix4Y_7pm9PiApq8xGBOOrPceMz8S7-o0N00XJzugK7mSkWryRN-MbJgyVvpY9Y1usH0dLZaz_1m0KOL3l6E0sXpbiSnQgYOXmg594xDj3Ve9iuN9BnHHtjhN0ilak6N-X85qJxI4oeVNqhdjypYoVQG1J-gb3i4dfNa34cdO8M5Nj_YZIzxzA48d_ykHMwAnnaYanfTzs5N3PTkPZcoawD50r9xdtFJmvJlR7R2PeoVa8UcxwV8-AslTwoTec_NArPXuIwrJ-D7w3Sk8tIuCaBz_booD74I1D0771IIvSEEBspFhvX07JDfw9eWFQ";

        internal static SigningCredentials DefaultSigningCredentials => KeyingMaterial.RsaSigningCreds_2048;

        internal static EncryptingCredentials DefaultEncryptingCredentials => KeyingMaterial.DefaultSymmetricEncryptingCreds_Aes128_Sha2;

        internal static TokenValidationParameters DefaultTokenValidationParameters => new TokenValidationParameters()
        {
            IssuerSigningKey = KeyingMaterial.RsaSigningCreds_2048_Public.Key,
            ValidIssuer = Default.Issuer,
            ValidAudience = Default.Audience,
            TokenDecryptionKey = DefaultEncryptingCredentials.Key,
            ValidateLifetime = false,
        };

        internal static JObject DefaultAccessTokenPayload => new JObject
        {
            { JwtRegisteredClaimNames.Email, "Bob@contoso.com" },
            { JwtRegisteredClaimNames.GivenName, "Bob" },
            { JwtRegisteredClaimNames.Iss, Default.Issuer },
            { JwtRegisteredClaimNames.Aud, Default.Audience },
            { JwtRegisteredClaimNames.Iat, EpochTime.GetIntDate(Default.IssueInstant).ToString() },
            { JwtRegisteredClaimNames.Nbf, EpochTime.GetIntDate(Default.NotBefore).ToString()},
            { JwtRegisteredClaimNames.Exp, EpochTime.GetIntDate(Default.Expires).ToString() },
        };

        internal static JObject DefaultJwk => new JObject
        {
            { "kty", "RSA" },
            { "n",  KeyingMaterial.RsaParameters_2048.Modulus},
            { "e", KeyingMaterial.RsaParameters_2048.Exponent },
            { JwtHeaderParameterNames.Alg, SecurityAlgorithms.RsaSha256 },
            { JwtHeaderParameterNames.Kid, KeyingMaterial.RsaSecurityKey_2048.KeyId }
        };

        internal static JObject DefaultJwkEcdsa => new JObject
        {
            { "kty", "EC" },
            { JwtHeaderParameterNames.Alg, SecurityAlgorithms.EcdsaSha256 },
            { JsonWebKeyParameterNames.Use, "sig" },
            { JsonWebKeyParameterNames.Crv, "P-256" },
            { JwtHeaderParameterNames.Kid, KeyingMaterial.RsaSecurityKey_2048.KeyId },
            { JsonWebKeyParameterNames.X, "luR290c8sXxbOGhNquQ3J3rh763Os4D609cHK-L_5fA" },
            { JsonWebKeyParameterNames.Y, "tUqUwtaVHwc7_CXnuBrCpMQTF5BJKdFnw9_JkSIXWpQ" }
        };

        internal static JObject InvalidJwk => new JObject
        {
            { "kty", "RSA" },
            { "e", "bad_data" },
            { JwtHeaderParameterNames.Alg, SecurityAlgorithms.RsaSha256 },
            { JwtHeaderParameterNames.Kid, KeyingMaterial.RsaSecurityKey_2048.KeyId }
        };

        internal static JObject DefaultCnfJwk => new JObject
        {
            { JwtHeaderParameterNames.Jwk, DefaultJwk },
        };

        internal static JObject DefaultJwe => new JObject
        {
            { JsonWebKeyParameterNames.Kty, JsonWebAlgorithmsKeyTypes.Octet },
            { JwtHeaderParameterNames.Alg, SecurityAlgorithms.Aes128CbcHmacSha256 },
            { JsonWebKeyParameterNames.K, KeyingMaterial.DefaultSymmetricKeyEncoded_256 }
        };

        internal static JObject DefaultCnfJwe => new JObject
        {
            { ClaimTypes.Jwe, EncryptToken(DefaultJwe.ToString(Formatting.None)) },
        };

        internal static JObject DefaultJku => new JObject
        {
            { JwtHeaderParameterNames.Jku, "jku.json" },
        };

        internal static JObject DefaultJkuKid => new JObject
        {
            { JwtHeaderParameterNames.Jku, "jku.json" },
            { JwtHeaderParameterNames.Kid, KeyingMaterial.RsaSecurityKey_2048.KeyId }
        };

        internal static JObject DefaultKid => new JObject
        {
            { JwtHeaderParameterNames.Kid, KeyingMaterial.RsaSecurityKey_2048.KeyId }
        };



        internal static JObject DefaultSignedHttpRequestHeader => new JObject
        {
            { JwtHeaderParameterNames.Alg, SecurityAlgorithms.RsaSha256 },
            { JwtHeaderParameterNames.Typ, PopConstants.SignedHttpRequest.TokenType },
            { JwtHeaderParameterNames.Kid, KeyingMaterial.RsaSecurityKey_2048.KeyId }
        };

        internal static JObject DefaultSignedHttpRequestPayload => new JObject
        {
            { ClaimTypes.At, DefaultEncodedAccessToken},
            { ClaimTypes.Ts, (long)(DateTime.UtcNow - EpochTime.UnixEpoch).TotalSeconds},
            { ClaimTypes.M, "GET"},
            { ClaimTypes.U, "www.contoso.com"},
            { ClaimTypes.P, "/path1"},
            { ClaimTypes.Q, "[[\"b\",\"a\",\"c\"],\"u4LgkGUWhP9MsKrEjA4dizIllDXluDku6ZqCeyuR-JY\"]" },
            { ClaimTypes.H, "[[\"content-type\",\"etag\"],\"P6z5XN4tTzHkfwe3XO1YvVUIurSuhvh_UG10N_j-aGs\"]" },
            { ClaimTypes.B, "ZK-O2gzHjpsCGped6sUL2EM20Z9T-uF07LCGMA88UFw" },
            { ClaimTypes.Nonce, "81da490f46c3494eba8c6e25a45a4d0f" }
        };

        internal static string CreateAt(JObject cnf, bool encrypt)
        {
            var accessToken = DefaultAccessTokenPayload;
            accessToken.Add(ClaimTypes.Cnf, cnf);

            if (encrypt)
                return new JsonWebTokenHandler().CreateToken(accessToken.ToString(Formatting.None), SignedHttpRequestTestUtils.DefaultSigningCredentials, KeyingMaterial.DefaultSymmetricEncryptingCreds_Aes128_Sha2, new Dictionary<string, object>() { { System.IdentityModel.Tokens.Jwt.JwtHeaderParameterNames.Typ, PopConstants.SignedHttpRequest.TokenType } });

            return new JsonWebTokenHandler().CreateToken(accessToken.ToString(Formatting.None), SignedHttpRequestTestUtils.DefaultSigningCredentials, new Dictionary<string, object>() { { System.IdentityModel.Tokens.Jwt.JwtHeaderParameterNames.Typ, PopConstants.SignedHttpRequest.TokenType } });
        }

        internal static string EncryptToken(string innerJwt)
        {
            return new JsonWebTokenHandler().EncryptToken(innerJwt, DefaultEncryptingCredentials);
        }

        internal static JsonWebToken ReplaceOrAddPropertyAndCreateDefaultSignedHttpRequest(JProperty newProperty)
        {
            JObject token = DefaultSignedHttpRequestPayload;

            if (token.ContainsKey(newProperty.Name))
                token.Property(newProperty.Name).Remove();

            if (newProperty.Value != null)
                token.Add(newProperty);

            return CreateDefaultSignedHttpRequestToken(token.ToString(Formatting.None));
        }

        internal static JsonWebToken CreateDefaultSignedHttpRequestToken(string signedHttpRequestTokenPayload)
        {
            var signingCredentials = SignedHttpRequestTestUtils.DefaultSigningCredentials;
            var popHeaderTyp = new Dictionary<string, object>() { { System.IdentityModel.Tokens.Jwt.JwtHeaderParameterNames.Typ, PopConstants.SignedHttpRequest.TokenType } };
            return new JsonWebToken(new JsonWebTokenHandler().CreateToken(signedHttpRequestTokenPayload, signingCredentials, popHeaderTyp));
        }

        internal static string CalculateBase64UrlEncodedHash(string data)
        {
            return CalculateBase64UrlEncodedHash(Encoding.UTF8.GetBytes(data));
        }

        internal static string CalculateBase64UrlEncodedHash(byte[] bytes)
        {
            using (var hash = SHA256.Create())
            {
                var hashedBytes = hash.ComputeHash(bytes);
                return Base64UrlEncoder.Encode(hashedBytes);
            }
        }

        internal static HttpHeaders CreateHttpHeaders(List<KeyValuePair<string, string>> headerKeyValuePairs)
        {
            using (var client = new HttpClient())
            {
                var headers = client.DefaultRequestHeaders;
                foreach(var headerKeyValuePair in headerKeyValuePairs)
                    headers.Add(headerKeyValuePair.Key, headerKeyValuePair.Value);

                return headers;
            }
        }

        internal static HttpRequestMessage CreateHttpRequestMessage(HttpMethod method, Uri uri, List<KeyValuePair<string, string>> headers, byte[] content, List<KeyValuePair<string, string>> contentHeaders = null)
        {
            var message = new HttpRequestMessage()
            {
                RequestUri = uri,
                Method = method,
            };

            foreach (var header in headers)
                message.Headers.Add(header.Key, header.Value);

            if (content != null)
                message.Content = new ByteArrayContent(content);

            if (contentHeaders != null)
                foreach (var contentHeader in contentHeaders)
                    message.Content.Headers.Add(contentHeader.Key, contentHeader.Value);

            return message;
        }

        internal static HttpResponseMessage CreateHttpResponseMessage(string json)
        {
            return new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(json, Encoding.UTF8, "application/json") };
        }

        internal static HttpClient SetupHttpClientThatReturns(string json)
        {
            return new HttpClient(new MockHttpMessageHandler(CreateHttpResponseMessage(json)));
        }
    }

    public class MockHttpMessageHandler : HttpMessageHandler
    {
        private HttpResponseMessage _httpResponseMessage;

        public MockHttpMessageHandler(HttpResponseMessage httpResponseMessage)
        {
            _httpResponseMessage = httpResponseMessage;
        }

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            return await Task.FromResult(_httpResponseMessage);
        }
    }
}

