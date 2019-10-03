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
using System.Threading;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Json;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Protocols.Pop.SignedHttpRequest;
using Microsoft.IdentityModel.TestUtils;
using Microsoft.IdentityModel.Tokens;
using Xunit;

#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant

namespace Microsoft.IdentityModel.Protocols.Pop.Tests.SignedHttpRequest
{
    public class PopResolvingTests
    {
        [Theory, MemberData(nameof(ResolvePopKeyAsyncTheoryData))]
        public async Task ResolvePopKeyAsync(ResolvePopKeyTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.ResolvePopKeyTheoryData", theoryData);
            try
            {
                var signedHttpRequestValidationData = theoryData.BuildSignedHttpRequestValidationData();
                var handler = new SignedHttpRequestHandlerPublic();
                _ = await handler.ResolvePopKeyPublicAsync(theoryData.ValidatedAccessToken, signedHttpRequestValidationData, CancellationToken.None).ConfigureAwait(false);

                if ((bool)signedHttpRequestValidationData.CallContext.PropertyBag[theoryData.MethodToCall] == false)
                    context.AddDiff($"{theoryData.MethodToCall} was not called.");

                theoryData.ExpectedException.ProcessNoException(context);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<ResolvePopKeyTheoryData> ResolvePopKeyAsyncTheoryData
        {
            get
            {
                var accessToken = new JsonWebToken(SignedHttpRequestTestUtils.DefaultEncodedAccessToken);
                return new TheoryData<ResolvePopKeyTheoryData>
                {
                    new ResolvePopKeyTheoryData
                    {
                        First = true,
                        MethodToCall = "trackResolvePopKeyFromJwk",
                        CallContext = new CallContext()
                        {
                            PropertyBag = new Dictionary<string, object>()
                            {
                                { "mockGetCnfClaimValue_returnJwk", null },
                                { "trackResolvePopKeyFromJwk", false }
                            }
                        },
                        ValidatedAccessToken = accessToken,
                        TestId = "ValidJwk",
                    },
                    new ResolvePopKeyTheoryData
                    {
                        MethodToCall = "trackResolvePopKeyFromJwe",
                        CallContext = new CallContext()
                        {
                            PropertyBag = new Dictionary<string, object>()
                            {
                                { "mockGetCnfClaimValue_returnJwe", null },
                                { "trackResolvePopKeyFromJwe", false }
                            }
                        },
                        ValidatedAccessToken = accessToken,
                        TestId = "ValidJwe",
                    },
                    new ResolvePopKeyTheoryData
                    {
                        MethodToCall = "trackResolvePopKeyFromJku",
                        CallContext = new CallContext()
                        {
                            PropertyBag = new Dictionary<string, object>()
                            {
                                { "mockGetCnfClaimValue_returnJku", null },
                                { "trackResolvePopKeyFromJku", false }
                            }
                        },
                        ValidatedAccessToken = accessToken,
                        TestId = "ValidJku",
                    },
                    new ResolvePopKeyTheoryData
                    {
                        MethodToCall = "trackResolvePopKeyFromJkuKid",
                        CallContext = new CallContext()
                        {
                            PropertyBag = new Dictionary<string, object>()
                            {
                                { "mockGetCnfClaimValue_returnJkuKid", null },
                                { "trackResolvePopKeyFromJkuKid", false }
                            }
                        },
                        ValidatedAccessToken = accessToken,
                        TestId = "ValidJkuKid",
                    },
                    new ResolvePopKeyTheoryData
                    {
                        MethodToCall = "trackResolvePopKeyFromKid",
                        CallContext = new CallContext()
                        {
                            PropertyBag = new Dictionary<string, object>()
                            {
                                { "mockGetCnfClaimValue_returnKid", null },
                                { "trackResolvePopKeyFromKid", false }
                            }
                        },
                        ValidatedAccessToken = accessToken,
                        TestId = "ValidKid",
                    },
                    new ResolvePopKeyTheoryData
                    {
                        CallContext = new CallContext()
                        {
                            PropertyBag = new Dictionary<string, object>()
                            {
                                { "mockGetCnfClaimValue_returnCustom", null },
                            }
                        },
                        ValidatedAccessToken = accessToken,
                        ExpectedException = new ExpectedException(typeof(SignedHttpRequestInvalidCnfClaimException), "IDX23014"),
                        TestId = "InvalidCnfClaim",
                    },
                };
            }
        }

        [Theory, MemberData(nameof(ResolvePopKeyFromJwkTheoryData))]
        public void ResolvePopKeyFromJwk(ResolvePopKeyTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.ResolvePopKeyTheoryData", theoryData);
            try
            {
                var signedHttpRequestValidationData = theoryData.BuildSignedHttpRequestValidationData();
                var handler = new SignedHttpRequestHandlerPublic();
                _ = handler.ResolvePopKeyFromJwkPublic(theoryData.PopKeyString, signedHttpRequestValidationData);

                theoryData.ExpectedException.ProcessNoException(context);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<ResolvePopKeyTheoryData> ResolvePopKeyFromJwkTheoryData
        {
            get
            {
                return new TheoryData<ResolvePopKeyTheoryData>
                {
                    new ResolvePopKeyTheoryData
                    {
                        First = true,
                        PopKeyString = null,
                        ExpectedException = ExpectedException.ArgumentNullException(),
                        TestId = "InvalidNullPopKey",
                    },
                    new ResolvePopKeyTheoryData
                    {
                        PopKeyString = string.Empty,
                        ExpectedException = ExpectedException.ArgumentNullException(),
                        TestId = "InvalidEmptyPopKey",
                    },
                    new ResolvePopKeyTheoryData
                    {
                        PopKeyString = "dummy",
                        ExpectedException = new ExpectedException(typeof(ArgumentException), "IDX10805", null, true),
                        TestId = "InvalidPopKeyNotAJWK",
                    },
                    new ResolvePopKeyTheoryData
                    {
                        PopKeyString = SignedHttpRequestTestUtils.DefaultJwe.ToString(Formatting.None),
                        ExpectedException = new ExpectedException(typeof(SignedHttpRequestInvalidPopKeyException), "IDX23015"),
                        TestId = "InvalidPopKeyNotSymmetricKey",
                    },
                    new ResolvePopKeyTheoryData
                    {
                        PopKeyString = SignedHttpRequestTestUtils.InvalidJwk.ToString(Formatting.None),
                        ExpectedException = new ExpectedException(typeof(SignedHttpRequestInvalidPopKeyException), "IDX23016"),
                        TestId = "InvalidPopKeyRsa",
                    },
                    new ResolvePopKeyTheoryData
                    {
                        PopKeyString = SignedHttpRequestTestUtils.DefaultJwkEcdsa.ToString(Formatting.None),
                        TestId = "ValidEcdsa",
                    },
                    new ResolvePopKeyTheoryData
                    {
                        PopKeyString = SignedHttpRequestTestUtils.DefaultJwk.ToString(Formatting.None),
                        TestId = "ValidRsa",
                    },
                };
            }
        }
    }

    public class ResolvePopKeyTheoryData : TheoryDataBase
    {
        public SignedHttpRequestValidationData BuildSignedHttpRequestValidationData()
        {
            var httpRequestData = new HttpRequestData()
            {
                Body = HttpRequestBody,
                Uri = HttpRequestUri,
                Method = HttpRequestMethod,
                Headers = HttpRequestHeaders
            };

            var tokenValidationParameters = SignedHttpRequestTestUtils.DefaultTokenValidationParameters;

            // add testId for debugging purposes
            var callContext = CallContext;
            if (callContext.PropertyBag == null)
                callContext.PropertyBag = new Dictionary<string, object>() { { "testId", TestId } };
            else
                callContext.PropertyBag.Add("testId", TestId);

            // set SignedHttpRequestToken if set and if JsonWebToken, otherwise set "dummy" value
            return new SignedHttpRequestValidationData(SignedHttpRequestToken is JsonWebToken jwt ? jwt.EncodedToken : "dummy", httpRequestData, tokenValidationParameters, SignedHttpRequestValidationPolicy, callContext);
        }

        public CallContext CallContext { get; set; } = CallContext.Default;

        public string MethodToCall { get; set; }

        public Uri HttpRequestUri { get; set; }

        public string HttpRequestMethod { get; set; }

        public IDictionary<string, IEnumerable<string>> HttpRequestHeaders { get; set; }

        public byte[] HttpRequestBody { get; set; }

        public SignedHttpRequestValidationPolicy SignedHttpRequestValidationPolicy { get; set; } = new SignedHttpRequestValidationPolicy()
        {
            ValidateB = true,
            ValidateH = true,
            ValidateM = true,
            ValidateP = true,
            ValidateQ = true,
            ValidateTs = true,
            ValidateU = true
        };

        public SigningCredentials SigningCredentials { get; set; } = SignedHttpRequestTestUtils.DefaultSigningCredentials;

        public string Token { get; set; } = SignedHttpRequestTestUtils.DefaultEncodedAccessToken;

        public SecurityToken SignedHttpRequestToken { get; set; }

        public SecurityToken ValidatedAccessToken { get; set; }

        public string PopKeyString { get; set; }
    }
}

#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
