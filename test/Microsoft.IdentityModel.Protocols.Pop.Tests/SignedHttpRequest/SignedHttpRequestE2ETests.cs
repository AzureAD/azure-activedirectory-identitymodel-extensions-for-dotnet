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
using System.Threading.Tasks;
using Microsoft.IdentityModel.TestUtils;

#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant

namespace Microsoft.IdentityModel.Protocols.Pop.Tests.SignedHttpRequest
{
    public class SignedHttpRequestE2ETests
    {
        [Theory, MemberData(nameof(RoundtripTheoryData))]
        public async Task Roundtrips(RoundtripSignedHttpRequestTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.Roundtrips", theoryData);
            try
            {
                var handler = new SignedHttpRequestHandler();
                var signedHttpRequestCreationData = new SignedHttpRequestCreationData(theoryData.AccessToken, theoryData.HttpRequestData, theoryData.SigningCredentials, theoryData.SignedHttpRequestCreationPolicy);
                var signedHttpRequest = await handler.CreateSignedHttpRequestAsync(signedHttpRequestCreationData, CancellationToken.None).ConfigureAwait(false);
                var signedHttpRequestValidationData = new SignedHttpRequestValidationData(signedHttpRequest, theoryData.HttpRequestData, theoryData.TokenValidationParameters, theoryData.SignedHttpRequestValidationPolicy);
                var result = await handler.ValidateSignedHttpRequestAsync(signedHttpRequestValidationData, CancellationToken.None).ConfigureAwait(false);

                Assert.NotNull(result);
                Assert.NotNull(result.SignedHttpRequest);
                Assert.NotNull(result.ValidatedSignedHttpRequest);
                Assert.NotNull(result.AccessToken);
                Assert.NotNull(result.ValidatedAccessToken);
                Assert.NotNull(result.ClaimsIdentity);

                theoryData.ExpectedException.ProcessNoException(context);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<RoundtripSignedHttpRequestTheoryData> RoundtripTheoryData
        {
            get
            {
                var body = Guid.NewGuid().ToByteArray();
                var httpRequestData = new HttpRequestData()
                {
                    Method = "GET",
                    Uri = new Uri("https://www.contoso.com:443/it/requests?b=bar&a=foo&c=duck"),
                    Body = body,
                    Headers = new Dictionary<string, IEnumerable<string>>
                    {
                        { "Content-Type", new List<string> { "application/json" } },
                        { "Content-Length", new List<string> { body.Length.ToString() } },
                        { "Etag", new List<string> { "742-3u8f34-3r2nvv3" } },
                    }
                };

                var httpRequestMessage = SignedHttpRequestTestUtils.CreateHttpRequestMessage
                (
                    HttpMethod.Get,
                    new Uri("https://www.contoso.com:443/it/requests?b=bar&a=foo&c=duck"),
                    new List<KeyValuePair<string, string>>()
                    {
                        new KeyValuePair<string, string>("Etag", "742-3u8f34-3r2nvv3")
                    },
                    body,
                    new List<KeyValuePair<string, string>>()
                    {
                        new KeyValuePair<string, string>("Content-Type", "application/json")
                    }
                );

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

                var tvpWrongIssuerSigningKey = SignedHttpRequestTestUtils.DefaultTokenValidationParameters;
                tvpWrongIssuerSigningKey.IssuerSigningKey = KeyingMaterial.RsaSecurityKey2;
                var ecdsaSigningCredentials = new SigningCredentials(KeyingMaterial.Ecdsa256Key, SecurityAlgorithms.EcdsaSha256);

                return new TheoryData<RoundtripSignedHttpRequestTheoryData>
                {
                    new RoundtripSignedHttpRequestTheoryData
                    {
                        First = true,
                        SignedHttpRequestCreationPolicy = creationPolicy,
                        SignedHttpRequestValidationPolicy = validationPolicy,
                        TokenValidationParameters = SignedHttpRequestTestUtils.DefaultTokenValidationParameters,
                        HttpRequestData = httpRequestData,
                        AccessToken = SignedHttpRequestTestUtils.DefaultEncodedAccessToken,
                        SigningCredentials = SignedHttpRequestTestUtils.DefaultSigningCredentials,
                        TestId = "ValidJwkRsa",
                    },
                    new RoundtripSignedHttpRequestTheoryData
                    {
                        SignedHttpRequestCreationPolicy = creationPolicy,
                        SignedHttpRequestValidationPolicy = validationPolicy,
                        TokenValidationParameters = SignedHttpRequestTestUtils.DefaultTokenValidationParameters,
                        HttpRequestData = PopUtilities.ToHttpRequestDataAsync(httpRequestMessage).ConfigureAwait(false).GetAwaiter().GetResult(),
                        AccessToken = SignedHttpRequestTestUtils.DefaultEncodedAccessToken,
                        SigningCredentials = SignedHttpRequestTestUtils.DefaultSigningCredentials,
                        TestId = "ValidJwkRsaUsingHttpRequestMessage",
                    },
                    new RoundtripSignedHttpRequestTheoryData
                    {
                        SignedHttpRequestCreationPolicy = creationPolicy,
                        SignedHttpRequestValidationPolicy = validationPolicy,
                        TokenValidationParameters = SignedHttpRequestTestUtils.DefaultTokenValidationParameters,
                        HttpRequestData = httpRequestData,
                        AccessToken = SignedHttpRequestTestUtils.EncryptToken(SignedHttpRequestTestUtils.DefaultEncodedAccessToken),
                        SigningCredentials = SignedHttpRequestTestUtils.DefaultSigningCredentials,
                        TestId = "ValidJwe",
                    },
                    new RoundtripSignedHttpRequestTheoryData
                    {
                        SignedHttpRequestCreationPolicy = creationPolicy,
                        SignedHttpRequestValidationPolicy = validationPolicy,
                        TokenValidationParameters = SignedHttpRequestTestUtils.DefaultTokenValidationParameters,
                        HttpRequestData = httpRequestData,
                        AccessToken = SignedHttpRequestTestUtils.CreateAt(SignedHttpRequestTestUtils.DefaultCnfJwkEcdsa, false),
                        SigningCredentials = ecdsaSigningCredentials,
                        TestId = "ValidJwkEcdsa",
                    },
                    new RoundtripSignedHttpRequestTheoryData
                    {
                        SignedHttpRequestCreationPolicy = new SignedHttpRequestCreationPolicy()
                        {
                            CreateU = false,
                            CreateB = true,
                            CreateH = true,
                            CreateM = true,
                            CreateP = true,
                            CreateQ = true,
                            CreateTs = true
                        },
                        SignedHttpRequestValidationPolicy = validationPolicy,
                        TokenValidationParameters = SignedHttpRequestTestUtils.DefaultTokenValidationParameters,
                        HttpRequestData = httpRequestData,
                        AccessToken = SignedHttpRequestTestUtils.EncryptToken(SignedHttpRequestTestUtils.DefaultEncodedAccessToken),
                        SigningCredentials = SignedHttpRequestTestUtils.DefaultSigningCredentials,
                        ExpectedException = new ExpectedException(typeof(SignedHttpRequestInvalidUClaimException), "IDX23003"),
                        TestId = "InvalidNoUClaim",
                    },
                    new RoundtripSignedHttpRequestTheoryData
                    {
                        SignedHttpRequestCreationPolicy = creationPolicy,
                        SignedHttpRequestValidationPolicy = validationPolicy,
                        TokenValidationParameters = tvpWrongIssuerSigningKey,
                        HttpRequestData = httpRequestData,
                        AccessToken = SignedHttpRequestTestUtils.EncryptToken(SignedHttpRequestTestUtils.DefaultEncodedAccessToken),
                        SigningCredentials = SignedHttpRequestTestUtils.DefaultSigningCredentials,
                        ExpectedException = new ExpectedException(typeof(SignedHttpRequestInvalidAtClaimException), "IDX23013", typeof(SecurityTokenSignatureKeyNotFoundException)),
                        TestId = "InvalidBadIssuerSigningKey",
                    },
                    new RoundtripSignedHttpRequestTheoryData
                    {
                        SignedHttpRequestCreationPolicy = creationPolicy,
                        SignedHttpRequestValidationPolicy = validationPolicy,
                        TokenValidationParameters = SignedHttpRequestTestUtils.DefaultTokenValidationParameters,
                        HttpRequestData = httpRequestData,
                        AccessToken = SignedHttpRequestTestUtils.EncryptToken(SignedHttpRequestTestUtils.DefaultEncodedAccessToken),
                        SigningCredentials = KeyingMaterial.X509SigningCreds_SelfSigned2048_SHA512,
                        ExpectedException = new ExpectedException(typeof(SignedHttpRequestInvalidSignatureException), "IDX23009"),
                        TestId = "InvalidBadPopSigningKey",
                    },
                };
            }
        }
    }

    public class RoundtripSignedHttpRequestTheoryData : TheoryDataBase
    {
        public string AccessToken { get; set; }
        public SignedHttpRequestValidationPolicy SignedHttpRequestValidationPolicy { get; set; }
        public TokenValidationParameters TokenValidationParameters { get; set; }
        public HttpRequestData HttpRequestData { get; set; }

        public Uri HttpRequestUri { get; set; }

        public string HttpRequestMethod { get; set; }

        public IDictionary<string, IEnumerable<string>> HttpRequestHeaders { get; set; }

        public byte[] HttpRequestBody { get; set; }

        public SignedHttpRequestCreationPolicy SignedHttpRequestCreationPolicy { get; set; } = new SignedHttpRequestCreationPolicy()
        {
            CreateB = true,
            CreateH = true,
            CreateM = true,
            CreateNonce = true,
            CreateP = true,
            CreateQ = true,
            CreateTs = true,
            CreateU = true
        };

        public Dictionary<string, object> Payload { get; set; } = new Dictionary<string, object>();

        public SigningCredentials SigningCredentials { get; set; } = SignedHttpRequestTestUtils.DefaultSigningCredentials;

        public string Token { get; set; } = SignedHttpRequestTestUtils.DefaultEncodedAccessToken;

        public string HeaderString { get; set; }

        public string PayloadString { get; set; }
    }
}

#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
