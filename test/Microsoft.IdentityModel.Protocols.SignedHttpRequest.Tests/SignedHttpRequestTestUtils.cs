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

namespace Microsoft.IdentityModel.Protocols.SignedHttpRequest.Tests
{
    public static class SignedHttpRequestTestUtils
    {
        // Default access token. Created using AcessTokenPayload (with DefaultCnfJwk) and SignedHttpRequestTestUtils.DefaultSigningCredentials
        // new JsonWebToken(SignedHttpRequestTestUtils.CreateAt(SignedHttpRequestTestUtils.DefaultCnfJwk, false)); 
        internal static string DefaultEncodedAccessToken = "eyJhbGciOiJSUzI1NiIsImtpZCI6IlJzYVNlY3VyaXR5S2V5XzIwNDgiLCJ0eXAiOiJwb3AifQ.eyJlbWFpbCI6IkJvYkBjb250b3NvLmNvbSIsImdpdmVuX25hbWUiOiJCb2IiLCJpc3MiOiJodHRwOi8vRGVmYXVsdC5Jc3N1ZXIuY29tIiwiYXVkIjoiaHR0cDovL0RlZmF1bHQuQXVkaWVuY2UuY29tIiwiaWF0IjoiMTQ4OTc3NTYxNyIsIm5iZiI6IjE0ODk3NzU2MTciLCJleHAiOiIxNjE2MDA2MDE3IiwiY25mIjp7Imp3ayI6eyJrdHkiOiJSU0EiLCJuIjoiNi1GckZrdF9UQnlRX0w1ZDdvci05UFZBb3dwc3d4VWUzZEplWUZUWTBMZ3E3ektJNU9RNVJuU3JJMFQ5eXJmblJ6RTlvT2RkNHptVmo5dHhWTEkteXlTdmluQXUzeVFEUW91MkdhNDJNTF8tSzRKcmQ1Y2xNVVBSR01iWGRWNVJsOXp6QjBzMkpvWkplZHVhNWR3b1F3MEdrUzVaOFlBWEJFelVMcnVwMDZmbkI1bjZ4NXIyeTFDXzhFYnA1Y3lFNEJqczdXNjhyVWx5SWx4MWx6WXZha3hTbmhVeFNzang3dV9tSWR5d3lHZmdpVDN0dzBGc1d2a2lfS1l1ckFQUjFCU01YaEN6elpUa01XS0U4SWFMa2hhdXc1TWR4b2p4eUJWdU5ZLUpfZWxxLUhnSl9kWks2Zzd2TU52WHoyX3ZULVN5a0lrendpRDllU0k5VVdmc2p3IiwiZSI6IkFRQUIiLCJhbGciOiJSUzI1NiIsImtpZCI6IlJzYVNlY3VyaXR5S2V5XzIwNDgifX19.aPR__XV6yb6soNrTMDi9VoxQgGZTCuojBGy49S-qvzQyaAYuPtl52htegtjqozQUrIuTBLDq-YUZRa2xPs5Y1dL1SWjGUu0wJadyDQzA6BUGL-67TQB-Mnwi2JIEHXYS1NWu3k09aOWhqQE-ovGgZGz7BjX4yRRAu70C09r0YG3ahaGkWHSfFJLeKG59BOmDuBlUUxe5Q8gJQR09iFY7knTPJLL3LWfM87W3chresTwNZV9eBFCRFAwAUMmPom4jee4TD7FmUuKLmTdKNdkw-Cmgj2Vf7McSK3aZtBgpu3va5O0vfD7_IBKA0SQJL3iBH4UT2Bmr5tzvyP7tix5W1A";

        // Default access token. Created using AcessTokenPayload (with DefaultCnfJwkThumprint) and SignedHttpRequestTestUtils.DefaultSigningCredentials
        // new JsonWebToken(SignedHttpRequestTestUtils.CreateAt(SignedHttpRequestTestUtils.DefaultCnfJwkThumprint, false)); 
        internal static string DefaultEncodedAccessTokenWithCnfThumprint = "eyJhbGciOiJSUzI1NiIsImtpZCI6IlJzYVNlY3VyaXR5S2V5XzIwNDgiLCJ0eXAiOiJwb3AifQ.eyJlbWFpbCI6IkJvYkBjb250b3NvLmNvbSIsImdpdmVuX25hbWUiOiJCb2IiLCJpc3MiOiJodHRwOi8vRGVmYXVsdC5Jc3N1ZXIuY29tIiwiYXVkIjoiaHR0cDovL0RlZmF1bHQuQXVkaWVuY2UuY29tIiwiaWF0IjoiMTQ4OTc3NTYxNyIsIm5iZiI6IjE0ODk3NzU2MTciLCJleHAiOiIxNjE2MDA2MDE3IiwiY25mIjp7ImtpZCI6Il9PM3pCTG4yaXVJV1gwNmdOUnBQNWNEc3psRFAyZlp6YklaN1dMTi1WV00ifX0.nZ0SsD6rIO3agzCT9KKBhgyb9d3tOABu6J-TzaLZ32UmJT53SbjGi_njXgjyWH1BsRPrqGaAUPIXOvRQh446tSgCDmAXhKJqp_yD-7-u6xHCco1bHSF_wXJOLA81ksKi2yXetjRibGRU-9j-lfM0UuEBN2TBRmxKzBqCImMaICCDOlm3egSaKpbowszA3z09cLyKbQiAXzCf7d00FW54eaJQJsNeowVMLi4J9YM9iF3dpoUVaF29BqAYVGrxynvlJ1j2sbtYWvwRn7PRMoS4TEtorLloTu7ihBSe8cV1NaO9H2pGQJaURbf1hu6pbP7PQ4v6lYyfrkuDC0GvzSEEEA";

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
            { "n",   Base64UrlEncoder.Encode(KeyingMaterial.RsaParameters_2048.Modulus)},
            { "e",  Base64UrlEncoder.Encode(KeyingMaterial.RsaParameters_2048.Exponent) },
            { JwtHeaderParameterNames.Alg, SecurityAlgorithms.RsaSha256 },
            { JwtHeaderParameterNames.Kid, KeyingMaterial.RsaSecurityKey_2048.KeyId }
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

        internal static JObject DefaultCnfJwkThumprint => new JObject
        {
            { JwtHeaderParameterNames.Kid, Base64UrlEncoder.Encode(new JsonWebKey(DefaultJwk.ToString(Formatting.None)).ComputeJwkThumbprint()) },
        };

        internal static JObject DefaultCnfJwkEcdsa => new JObject
        {
            { JwtHeaderParameterNames.Jwk, DefaultJwkEcdsa },
        };

        internal static JObject DefaultCnfJwkEcdsaThumbprint => new JObject
        {
            { JwtHeaderParameterNames.Kid, Base64UrlEncoder.Encode(new JsonWebKey(DefaultJwkEcdsa.ToString(Formatting.None)).ComputeJwkThumbprint()) },
        };

#if !NET_CORE
        internal static JObject DefaultJwkEcdsa => new JObject
        {
            { "kty", "EC" },
            { JwtHeaderParameterNames.Alg, SecurityAlgorithms.EcdsaSha256 },
            { JsonWebKeyParameterNames.Use, "sig" },
            { JsonWebKeyParameterNames.Crv, "P-256" },
            { JwtHeaderParameterNames.Kid, KeyingMaterial.Ecdsa256Key.KeyId },
            { JsonWebKeyParameterNames.X, "luR290c8sXxbOGhNquQ3J3rh763Os4D609cHK-L_5fA" },
            { JsonWebKeyParameterNames.Y, "tUqUwtaVHwc7_CXnuBrCpMQTF5BJKdFnw9_JkSIXWpQ" }
        };
#else
        internal static JObject DefaultJwkEcdsa => new JObject
        {
            { "kty", "EC" },
            { JwtHeaderParameterNames.Alg, SecurityAlgorithms.EcdsaSha256 },
            { JsonWebKeyParameterNames.Use, "sig" },
            { JsonWebKeyParameterNames.Crv, "P-256" },
            { JwtHeaderParameterNames.Kid, KeyingMaterial.Ecdsa256Key.KeyId },
            { JsonWebKeyParameterNames.X, Base64UrlEncoder.Encode(KeyingMaterial.Ecdsa256Parameters_Public.Q.X) },
            { JsonWebKeyParameterNames.Y, Base64UrlEncoder.Encode(KeyingMaterial.Ecdsa256Parameters_Public.Q.Y) }
        };
#endif
        internal static JObject DefaultJwe => new JObject
        {
            { JsonWebKeyParameterNames.Kty, JsonWebAlgorithmsKeyTypes.Octet },
            { JwtHeaderParameterNames.Alg, SecurityAlgorithms.Aes128CbcHmacSha256 },
            { JsonWebKeyParameterNames.K, KeyingMaterial.DefaultSymmetricKeyEncoded_256 }
        };

        internal static JObject DefaultCnfJwe => new JObject
        {
            { ConfirmationClaimTypes.Jwe, EncryptToken(DefaultJwe.ToString(Formatting.None)) },
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
            { JwtHeaderParameterNames.Typ, SignedHttpRequestConstants.TokenType },
            { JwtHeaderParameterNames.Kid, KeyingMaterial.RsaSecurityKey_2048.KeyId }
        };

        internal static JObject DefaultSignedHttpRequestPayload => new JObject
        {
            { SignedHttpRequestClaimTypes.At, DefaultEncodedAccessToken},
            { SignedHttpRequestClaimTypes.Ts, (long)(DateTime.UtcNow - EpochTime.UnixEpoch).TotalSeconds},
            { SignedHttpRequestClaimTypes.M, "GET"},
            { SignedHttpRequestClaimTypes.U, "www.contoso.com"},
            { SignedHttpRequestClaimTypes.P, "/path1"},
            { SignedHttpRequestClaimTypes.Q, "[[\"b\",\"a\",\"c\"],\"u4LgkGUWhP9MsKrEjA4dizIllDXluDku6ZqCeyuR-JY\"]" },
            { SignedHttpRequestClaimTypes.H, "[[\"content-type\",\"etag\"],\"P6z5XN4tTzHkfwe3XO1YvVUIurSuhvh_UG10N_j-aGs\"]" },
            { SignedHttpRequestClaimTypes.B, "ZK-O2gzHjpsCGped6sUL2EM20Z9T-uF07LCGMA88UFw" },
            { SignedHttpRequestClaimTypes.Nonce, "81da490f46c3494eba8c6e25a45a4d0f" },
            { ConfirmationClaimTypes.Cnf, JObject.Parse(SignedHttpRequestUtilities.CreateJwkClaim(JsonWebKeyConverter.ConvertFromRSASecurityKey(DefaultSigningCredentials.Key as RsaSecurityKey))) }
        };

        internal static string CreateAt(JObject cnf, bool encrypt, bool addCnf = true, bool addCnfAsString = false)
        {
            var accessToken = DefaultAccessTokenPayload;

            if (addCnf && !addCnfAsString)
                accessToken.Add(ConfirmationClaimTypes.Cnf, cnf);

            if (addCnf && addCnfAsString)
                accessToken.Add(ConfirmationClaimTypes.Cnf, cnf.ToString());

            if (encrypt)
                return new JsonWebTokenHandler().CreateToken(accessToken.ToString(Formatting.None), DefaultSigningCredentials, KeyingMaterial.DefaultSymmetricEncryptingCreds_Aes128_Sha2, new Dictionary<string, object>() { { System.IdentityModel.Tokens.Jwt.JwtHeaderParameterNames.Typ, SignedHttpRequestConstants.TokenType } });

            return new JsonWebTokenHandler().CreateToken(accessToken.ToString(Formatting.None), DefaultSigningCredentials, new Dictionary<string, object>() { { System.IdentityModel.Tokens.Jwt.JwtHeaderParameterNames.Typ, SignedHttpRequestConstants.TokenType } });
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
            var popHeaderTyp = new Dictionary<string, object>() { { System.IdentityModel.Tokens.Jwt.JwtHeaderParameterNames.Typ, SignedHttpRequestConstants.TokenType } };
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

            if (content != null)
            {
                message.Content = new ByteArrayContent(content);
                message.Content.Headers.ContentLength = content.Length;
            }

            foreach (var header in headers)
            { 
                message.Headers.Add(header.Key, header.Value);
            }

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

