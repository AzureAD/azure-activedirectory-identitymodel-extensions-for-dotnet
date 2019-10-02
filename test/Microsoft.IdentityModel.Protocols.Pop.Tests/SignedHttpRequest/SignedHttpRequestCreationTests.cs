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
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Json;
using Microsoft.IdentityModel.Json.Linq;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Protocols.Pop.SignedHttpRequest;
using Microsoft.IdentityModel.TestUtils;
using Microsoft.IdentityModel.Tokens;
using Xunit;

#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant

namespace Microsoft.IdentityModel.Protocols.Pop.Tests.SignedHttpRequest
{
    public class SignedHttpRequestCreationTests
    {
        [Fact]
        public async Task CreateSignedHttpRequest()
        {
            var context = TestUtilities.WriteHeader($"{this}.CreateSignedHttpRequest", "", true);

            var handler = new SignedHttpRequestHandlerPublic();
            await Assert.ThrowsAsync<ArgumentNullException>(async () => await handler.CreateSignedHttpRequestPublicAsync(null, CancellationToken.None).ConfigureAwait(false));

            var signedHttpRequestCreationData = new SignedHttpRequestCreationData(ReferenceTokens.JWSWithDifferentTyp, new HttpRequestData(), Default.AsymmetricSigningCredentials, new SignedHttpRequestCreationPolicy() { CreateM = false, CreateP = false, CreateU = false });
            var signedHttpRequestString = await handler.CreateSignedHttpRequestPublicAsync(signedHttpRequestCreationData, CancellationToken.None).ConfigureAwait(false);

            var tvp = new TokenValidationParameters()
            {
                ValidateAudience = false,
                ValidateIssuer = false,
                ValidateIssuerSigningKey = false,
                ValidateLifetime = false,
                IssuerSigningKey = signedHttpRequestCreationData.SigningCredentials.Key
            };
            var result = new JsonWebTokenHandler().ValidateToken(signedHttpRequestString, tvp);

            if (result.IsValid == false)
                context.AddDiff($"Not able to create and validate signed http request token");

            TestUtilities.AssertFailIfErrors(context);
        }

        [Theory, MemberData(nameof(CreateHeaderTheoryData))]
        public void CreateHeader(CreateSignedHttpRequestTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.CreateHeader", theoryData);
            try
            {
                var handler = new SignedHttpRequestHandlerPublic();
                var signedHttpRequestCreationData = theoryData.BuildSignedHttpRequestCreationData();

                var headerString = handler.CreateHttpRequestHeaderPublic(signedHttpRequestCreationData);
                var header = JObject.Parse(headerString);

                if (!header.ContainsKey(theoryData.ExpectedClaim))
                    context.AddDiff($"Header doesn't contain the claim '{theoryData.ExpectedClaim}'");

                if (!IdentityComparer.AreEqual(header.Value<string>(theoryData.ExpectedClaim), theoryData.ExpectedClaimValue))
                    context.AddDiff($"Value of '{theoryData.ExpectedClaim}' claim is '{header.Value<string>(theoryData.ExpectedClaim)}', but expected value was '{theoryData.ExpectedClaimValue}'");

                theoryData.ExpectedException.ProcessNoException(context);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<CreateSignedHttpRequestTheoryData> CreateHeaderTheoryData
        {
            get
            {
                return new TheoryData<CreateSignedHttpRequestTheoryData>
                {
                    new CreateSignedHttpRequestTheoryData
                    {
                        First = true,
                        ExpectedClaim = JwtHeaderParameterNames.Typ,
                        ExpectedClaimValue = PopConstants.SignedHttpRequest.TokenType,
                        TestId = "ExpectedTokenType",
                    },
                    new CreateSignedHttpRequestTheoryData
                    {
                        ExpectedClaim = JwtHeaderParameterNames.Kid,
                        ExpectedClaimValue =  Default.AsymmetricSigningCredentials.Kid,
                        SigningCredentials = Default.AsymmetricSigningCredentials,
                        TestId = "ExpectedKid",
                    },
                    new CreateSignedHttpRequestTheoryData
                    {
                        ExpectedClaim = JwtHeaderParameterNames.X5t,
                        ExpectedClaimValue =  ((X509SecurityKey)Default.AsymmetricSigningCredentials.Key).X5t,
                        SigningCredentials = Default.AsymmetricSigningCredentials,
                        TestId = "ExpectedX5t",
                    },
                };
            }
        }

        [Theory, MemberData(nameof(SignHttpRequestTheoryData))]
        public async void SignHttpRequest(CreateSignedHttpRequestTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.SignHttpRequest", theoryData);
            try
            {
                var handler = new SignedHttpRequestHandlerPublic();
                var signedHttpRequestCreationData = theoryData.BuildSignedHttpRequestCreationData();
                var signedHttpRequestString = await handler.SignHttpRequestPublicAsync(theoryData.HeaderString, theoryData.PayloadString, signedHttpRequestCreationData, CancellationToken.None).ConfigureAwait(false);

                var tvp = new TokenValidationParameters()
                {
                    ValidateAudience = false,
                    ValidateIssuer = false,
                    ValidateIssuerSigningKey = false,
                    ValidateLifetime = false,
                    IssuerSigningKey = signedHttpRequestCreationData.SigningCredentials.Key
                };
                var result = new JsonWebTokenHandler().ValidateToken(signedHttpRequestString, tvp);

                if (result.IsValid == false)
                    context.AddDiff($"Not able to create and validate signed http request token");

                theoryData.ExpectedException.ProcessNoException(context);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<CreateSignedHttpRequestTheoryData> SignHttpRequestTheoryData
        {
            get
            {
                return new TheoryData<CreateSignedHttpRequestTheoryData>
                {
                    new CreateSignedHttpRequestTheoryData
                    {
                        First = true,
                        HeaderString = null,
                        ExpectedException = ExpectedException.ArgumentNullException(),
                        TestId = "HeaderStringNull",
                    },
                    new CreateSignedHttpRequestTheoryData
                    {
                        HeaderString = "",
                        ExpectedException = ExpectedException.ArgumentNullException(),
                        TestId = "HeaderStringEmpty",
                    },
                    new CreateSignedHttpRequestTheoryData
                    {
                        HeaderString = "dummyData",
                        PayloadString = null,
                        ExpectedException = ExpectedException.ArgumentNullException(),
                        TestId = "PayloadStringNull",
                    },
                    new CreateSignedHttpRequestTheoryData
                    {
                        HeaderString = "dummyData",
                        PayloadString = "",
                        ExpectedException = ExpectedException.ArgumentNullException(),
                        TestId = "PayloadStringEmpty",
                    },
                    new CreateSignedHttpRequestTheoryData
                    {
                        HeaderString = "{\"alg\": \"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\"}",
                        PayloadString = "{\"claim\": 1}",
                        SigningCredentials = Default.AsymmetricSigningCredentials,
                        TestId = "ValidSignedHttpRequest",
                    },
                };
            }
        }

        [Theory, MemberData(nameof(CreateClaimCallsTheoryData))]
        public void CreateClaimCalls(CreateSignedHttpRequestTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.CreateClaimCalls", theoryData);
            try
            {
                var handler = new SignedHttpRequestHandlerPublic();
                var signedHttpRequestCreationData = theoryData.BuildSignedHttpRequestCreationData();

                var payloadString = handler.CreateHttpRequestPayloadPublic(signedHttpRequestCreationData);
                var payload = JObject.Parse(payloadString);

                foreach (var payloadItem in payload)
                {
                    if (!theoryData.ExpectedPayloadClaims.Contains(payloadItem.Key))
                        context.AddDiff($"ExpectedPayloadClaims doesn't contain the claim '{payloadItem.Key}'");
                }

                foreach (var expectedClaim in theoryData.ExpectedPayloadClaims)
                {
                    if (!payload.ContainsKey(expectedClaim))
                        context.AddDiff($"Payload doesn't contain the claim '{expectedClaim}'");
                }

                theoryData.ExpectedException.ProcessNoException(context);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<CreateSignedHttpRequestTheoryData> CreateClaimCallsTheoryData
        {
            get
            {
                return new TheoryData<CreateSignedHttpRequestTheoryData>
                {
                    new CreateSignedHttpRequestTheoryData
                    {
                        First = true,
                        ExpectedPayloadClaims = new List<string>() { "at" },
                        SignedHttpRequestCreationPolicy = new SignedHttpRequestCreationPolicy()
                        {
                            CreateB = false,
                            CreateH = false,
                            CreateM = false,
                            CreateNonce = false,
                            CreateP = false,
                            CreateQ = false,
                            CreateTs = false,
                            CreateU = false,
                            CustomNonceCreator = null,
                            AdditionalClaimCreator = null
                        },
                        TestId = "NoClaimsCreated",
                    },
                    new CreateSignedHttpRequestTheoryData
                    {
                        ExpectedPayloadClaims = new List<string>() { "at", "b", "h", "m", "nonce", "p", "q", "ts", "u", "additionalClaim" },
                        SignedHttpRequestCreationPolicy = new SignedHttpRequestCreationPolicy()
                        {
                            CreateB = true,
                            CreateH = true,
                            CreateM = true,
                            CreateNonce = true,
                            CreateP = true,
                            CreateQ = true,
                            CreateTs = true,
                            CreateU = true,
                            CustomNonceCreator = null,
                            AdditionalClaimCreator = (IDictionary<string, object> payload, SignedHttpRequestCreationData signedHttpRequestCreationData) => payload.Add("additionalClaim", "additionalClaimValue"),
                        },
                        HttpRequestBody = Guid.NewGuid().ToByteArray(),
                        HttpRequestHeaders = new Dictionary<string, IEnumerable<string>>()
                        {
                            { "header1", new List<string>() {"headerValue1"} }
                        },
                        HttpRequestMethod = "GET",
                        HttpRequestUri = new Uri("https://www.contoso.com/path1?queryParam1=quertValue1"),
                        TestId = "AllClaimsCreated",
                    },
                    new CreateSignedHttpRequestTheoryData
                    {
                        Payload = null,
                        ExpectedException = ExpectedException.ArgumentNullException(),
                        TestId = "NullPayload",
                    },
                };
            }
        }

        [Theory, MemberData(nameof(CreateAtClaimTheoryData))]
        public void CreateAtClaim(CreateSignedHttpRequestTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.CreateAtClaimTheoryData", theoryData);
            try
            {
                var handler = new SignedHttpRequestHandlerPublic();
                var signedHttpRequestCreationData = theoryData.BuildSignedHttpRequestCreationData();

                handler.AddAtClaimPublic(theoryData.Payload, signedHttpRequestCreationData);
                var payload = JObject.Parse(handler.ConvertToJsonPublic(theoryData.Payload));

                if (!payload.ContainsKey(theoryData.ExpectedClaim))
                    context.AddDiff($"Payload doesn't contain the claim '{theoryData.ExpectedClaim}'");

                if (!IdentityComparer.AreEqual(payload.Value<string>(theoryData.ExpectedClaim), theoryData.ExpectedClaimValue))
                    context.AddDiff($"Value of '{theoryData.ExpectedClaim}' claim is '{payload.Value<string>(theoryData.ExpectedClaim)}', but expected value was '{theoryData.ExpectedClaimValue}'");

                theoryData.ExpectedException.ProcessNoException(context);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<CreateSignedHttpRequestTheoryData> CreateAtClaimTheoryData
        {
            get
            {
                return new TheoryData<CreateSignedHttpRequestTheoryData>
                {
                    new CreateSignedHttpRequestTheoryData
                    {
                        First = true,
                        ExpectedClaim = PopConstants.SignedHttpRequest.ClaimTypes.At,
                        ExpectedClaimValue = ReferenceTokens.JWSWithDifferentTyp,
                        TestId = "ValidAt",
                    },
                    new CreateSignedHttpRequestTheoryData
                    {
                        Payload = null,
                        ExpectedException = ExpectedException.ArgumentNullException(),
                        TestId = "NullPayload",
                    },
                };
            }
        }

        [Theory, MemberData(nameof(CreateTsClaimTheoryData))]
        public void CreateTsClaim(CreateSignedHttpRequestTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.CreateTsClaim", theoryData);
            try
            {
                var handler = new SignedHttpRequestHandlerPublic();
                var signedHttpRequestCreationData = theoryData.BuildSignedHttpRequestCreationData();

                handler.AddTsClaimPublic(theoryData.Payload, signedHttpRequestCreationData);
                var payload = JObject.Parse(handler.ConvertToJsonPublic(theoryData.Payload));

                if (!payload.ContainsKey(theoryData.ExpectedClaim))
                    context.AddDiff($"Payload doesn't contain the claim '{theoryData.ExpectedClaim}'");

                if (!IdentityComparer.AreEqual(payload.Value<long>(theoryData.ExpectedClaim), theoryData.ExpectedClaimValue))
                    context.AddDiff($"Value of '{theoryData.ExpectedClaim}' claim is '{payload.Value<long>(theoryData.ExpectedClaim)}', but expected value was '{theoryData.ExpectedClaimValue}'");

                theoryData.ExpectedException.ProcessNoException(context);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<CreateSignedHttpRequestTheoryData> CreateTsClaimTheoryData
        {
            get
            {
                var timeNow = new DateTime(2019, 01, 01, 01, 01, 01, 01);
                return new TheoryData<CreateSignedHttpRequestTheoryData>
                {
                    new CreateSignedHttpRequestTheoryData
                    {
                        First = true,
                        CallContext = new CallContext() { PropertyBag = new Dictionary<string, object>() { {"MockAddTsClaim", timeNow } } },
                        ExpectedClaim = PopConstants.SignedHttpRequest.ClaimTypes.Ts,
                        ExpectedClaimValue = (long)(timeNow - EpochTime.UnixEpoch).TotalSeconds,
                        TestId = "ValidTs",
                    },
                    new CreateSignedHttpRequestTheoryData
                    {
                        CallContext = new CallContext() { PropertyBag = new Dictionary<string, object>() { {"MockAddTsClaim", timeNow } } },
                        SignedHttpRequestCreationPolicy = new SignedHttpRequestCreationPolicy() { TimeAdjustment = TimeSpan.FromMinutes(-1) },
                        ExpectedClaim = PopConstants.SignedHttpRequest.ClaimTypes.Ts,
                        ExpectedClaimValue = (long)(timeNow - EpochTime.UnixEpoch).TotalSeconds - 60,
                        TestId = "ValidTsWithTimeAdjustmentMinus",
                    },
                    new CreateSignedHttpRequestTheoryData
                    {
                        CallContext = new CallContext() { PropertyBag = new Dictionary<string, object>() { {"MockAddTsClaim", timeNow } } },
                        SignedHttpRequestCreationPolicy = new SignedHttpRequestCreationPolicy() { TimeAdjustment = TimeSpan.FromMinutes(1) },
                        ExpectedClaim = PopConstants.SignedHttpRequest.ClaimTypes.Ts,
                        ExpectedClaimValue = (long)(timeNow - EpochTime.UnixEpoch).TotalSeconds + 60,
                        TestId = "ValidTsWithTimeAdjustmentPlus",
                    },
                    new CreateSignedHttpRequestTheoryData
                    {
                        Payload = null,
                        ExpectedException = ExpectedException.ArgumentNullException(),
                        TestId = "NullPayload",
                    },
                };
            }
        }

        [Theory, MemberData(nameof(CreateMClaimTheoryData))]
        public void CreateMClaim(CreateSignedHttpRequestTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.CreateMClaim", theoryData);
            try
            {
                var handler = new SignedHttpRequestHandlerPublic();
                var signedHttpRequestCreationData = theoryData.BuildSignedHttpRequestCreationData();

                handler.AddMClaimPublic(theoryData.Payload, signedHttpRequestCreationData);
                var payload = JObject.Parse(handler.ConvertToJsonPublic(theoryData.Payload));

                if (!payload.ContainsKey(theoryData.ExpectedClaim))
                    context.AddDiff($"Payload doesn't contain the claim '{theoryData.ExpectedClaim}'");

                if (!IdentityComparer.AreEqual(payload.Value<string>(theoryData.ExpectedClaim), theoryData.ExpectedClaimValue))
                    context.AddDiff($"Value of '{theoryData.ExpectedClaim}' claim is '{payload.Value<string>(theoryData.ExpectedClaim)}', but expected value was '{theoryData.ExpectedClaimValue}'");

                theoryData.ExpectedException.ProcessNoException(context);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<CreateSignedHttpRequestTheoryData> CreateMClaimTheoryData
        {
            get
            {
                return new TheoryData<CreateSignedHttpRequestTheoryData>
                {
                    new CreateSignedHttpRequestTheoryData
                    {
                        First = true,
                        ExpectedClaim = PopConstants.SignedHttpRequest.ClaimTypes.M,
                        ExpectedClaimValue = "GET",
                        HttpRequestMethod = "GET",
                        TestId = "ValidM",
                    },
                    new CreateSignedHttpRequestTheoryData
                    {
                        ExpectedClaimValue = "GET",
                        HttpRequestMethod = "get",
                        ExpectedException = new ExpectedException(typeof(SignedHttpRequestCreationException), "IDX23002"),
                        TestId = "InvalidLowercaseM",
                    },
                    new CreateSignedHttpRequestTheoryData
                    {
                        Payload = null,
                        ExpectedException = ExpectedException.ArgumentNullException(),
                        TestId = "NullPayload",
                    },
                    new CreateSignedHttpRequestTheoryData
                    {
                        HttpRequestMethod = "",
                        ExpectedException = ExpectedException.ArgumentNullException(),
                        TestId = "EmptyM",
                    },
                };
            }
        }

        [Theory, MemberData(nameof(CreateUClaimTheoryData))]
        public void CreateUClaim(CreateSignedHttpRequestTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.CreateUClaim", theoryData);
            try
            {
                var handler = new SignedHttpRequestHandlerPublic();
                var signedHttpRequestCreationData = theoryData.BuildSignedHttpRequestCreationData();

                handler.AddUClaimPublic(theoryData.Payload, signedHttpRequestCreationData);
                var payload = JObject.Parse(handler.ConvertToJsonPublic(theoryData.Payload));

                if (!theoryData.Payload.ContainsKey(theoryData.ExpectedClaim))
                    context.AddDiff($"Payload doesn't contain the claim '{theoryData.ExpectedClaim}'");

                if (!IdentityComparer.AreEqual(payload.Value<string>(theoryData.ExpectedClaim), theoryData.ExpectedClaimValue))
                    context.AddDiff($"Value of '{theoryData.ExpectedClaim}' claim is '{payload.Value<string>(theoryData.ExpectedClaim)}', but expected value was '{theoryData.ExpectedClaimValue}'");

                theoryData.ExpectedException.ProcessNoException(context);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<CreateSignedHttpRequestTheoryData> CreateUClaimTheoryData
        {
            get
            {
                return new TheoryData<CreateSignedHttpRequestTheoryData>
                {
                    new CreateSignedHttpRequestTheoryData
                    {
                        First = true,
                        ExpectedClaim = PopConstants.SignedHttpRequest.ClaimTypes.U,
                        ExpectedClaimValue = "www.contoso.com",
                        HttpRequestUri = new Uri("https://www.contoso.com/path1?queryParam1=value1"),
                        TestId = "ValidU1",
                    },
                    new CreateSignedHttpRequestTheoryData
                    {
                        ExpectedClaim = PopConstants.SignedHttpRequest.ClaimTypes.U,
                        ExpectedClaimValue = "www.contoso.com",
                        HttpRequestUri = new Uri("http://www.Contoso.com/"),
                        TestId = "ValidU2",
                    },
                    new CreateSignedHttpRequestTheoryData
                    {
                        ExpectedClaim = PopConstants.SignedHttpRequest.ClaimTypes.U,
                        ExpectedClaimValue = "www.contoso.com",
                        HttpRequestUri = new Uri("https://www.contoso.com:443"),
                        TestId = "ValidU3",
                    },
                    new CreateSignedHttpRequestTheoryData
                    {
                        ExpectedClaim = PopConstants.SignedHttpRequest.ClaimTypes.U,
                        ExpectedClaimValue = "www.contoso.com:81",
                        HttpRequestUri = new Uri("https://www.contoso.com:81"),
                        TestId = "ValidU4",
                    },
                    new CreateSignedHttpRequestTheoryData
                    {
                        ExpectedClaim = PopConstants.SignedHttpRequest.ClaimTypes.U,
                        HttpRequestUri = new Uri("/relativePath", UriKind.Relative),
                        ExpectedException = new ExpectedException(typeof(SignedHttpRequestCreationException), "IDX23001"),
                        TestId = "InvalidRelativeUri",
                    },
                    new CreateSignedHttpRequestTheoryData
                    {
                        Payload = null,
                        ExpectedException = ExpectedException.ArgumentNullException(),
                        TestId = "NullPayload",
                    },
                    new CreateSignedHttpRequestTheoryData
                    {
                        HttpRequestUri = null,
                        ExpectedException = ExpectedException.ArgumentNullException(),
                        TestId = "NullUri",
                    },
                };
            }
        }

        [Theory, MemberData(nameof(CreatePClaimTheoryData))]
        public void CreatePClaim(CreateSignedHttpRequestTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.CreatePClaim", theoryData);
            try
            {
                var handler = new SignedHttpRequestHandlerPublic();
                var signedHttpRequestCreationData = theoryData.BuildSignedHttpRequestCreationData();

                handler.AddPClaimPublic(theoryData.Payload, signedHttpRequestCreationData);
                var payload = JObject.Parse(handler.ConvertToJsonPublic(theoryData.Payload));

                if (!payload.ContainsKey(theoryData.ExpectedClaim))
                    context.AddDiff($"Payload doesn't contain the claim '{theoryData.ExpectedClaim}'");

                if (!IdentityComparer.AreEqual(payload.Value<string>(theoryData.ExpectedClaim), theoryData.ExpectedClaimValue))
                    context.AddDiff($"Value of '{theoryData.ExpectedClaim}' claim is '{payload.Value<string>(theoryData.ExpectedClaim)}', but expected value was '{theoryData.ExpectedClaimValue}'");

                theoryData.ExpectedException.ProcessNoException(context);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<CreateSignedHttpRequestTheoryData> CreatePClaimTheoryData
        {
            get
            {
                return new TheoryData<CreateSignedHttpRequestTheoryData>
                {
                    new CreateSignedHttpRequestTheoryData
                    {
                        First = true,
                        ExpectedClaim = PopConstants.SignedHttpRequest.ClaimTypes.P,
                        ExpectedClaimValue = "/path1",
                        HttpRequestUri = new Uri("https://www.contoso.com/path1?queryParam1=value1"),
                        TestId = "ValidP1",
                    },
                    new CreateSignedHttpRequestTheoryData
                    {
                        ExpectedClaim = PopConstants.SignedHttpRequest.ClaimTypes.P,
                        ExpectedClaimValue = "/path1/",
                        HttpRequestUri = new Uri("https://www.contoso.com/path1/"),
                        TestId = "ValidP2",
                    },
                    new CreateSignedHttpRequestTheoryData
                    {
                        ExpectedClaim = PopConstants.SignedHttpRequest.ClaimTypes.P,
                        ExpectedClaimValue = "/path1",
                        HttpRequestUri = new Uri("https://www.contoso.com/path1"),
                        TestId = "ValidP3",
                    },
                    new CreateSignedHttpRequestTheoryData
                    {
                        ExpectedClaim = PopConstants.SignedHttpRequest.ClaimTypes.P,
                        ExpectedClaimValue = "/path1",
                        HttpRequestUri = new Uri("http://www.contoso.com:81/path1"),
                        TestId = "ValidP4",
                    },
                    new CreateSignedHttpRequestTheoryData
                    {
                        ExpectedClaim = PopConstants.SignedHttpRequest.ClaimTypes.P,
                        ExpectedClaimValue = "/pa%20th1",
                        HttpRequestUri = new Uri("http://www.contoso.com:81/pa th1"),
                        TestId = "ValidP5",
                    },
                    new CreateSignedHttpRequestTheoryData
                    {
                        ExpectedClaim = PopConstants.SignedHttpRequest.ClaimTypes.P,
                        ExpectedClaimValue = "/",
                        HttpRequestUri = new Uri("http://www.contoso.com"),
                        TestId = "NoPath",
                    },
                    new CreateSignedHttpRequestTheoryData
                    {
                        ExpectedClaim = PopConstants.SignedHttpRequest.ClaimTypes.P,
                        ExpectedClaimValue = "/relativePath",
                        HttpRequestUri = new Uri("/relativePath", UriKind.Relative),
                        TestId = "ValidRelativeUri",
                    },
                    new CreateSignedHttpRequestTheoryData
                    {
                        Payload = null,
                        ExpectedException = ExpectedException.ArgumentNullException(),
                        TestId = "NullPayload",
                    },
                    new CreateSignedHttpRequestTheoryData
                    {
                        HttpRequestUri = null,
                        ExpectedException = ExpectedException.ArgumentNullException(),
                        TestId = "NullUri",
                    },
                };
            }
        }

        [Theory, MemberData(nameof(CreateQClaimTheoryData))]
        public void CreateQClaim(CreateSignedHttpRequestTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.CreateQClaim", theoryData);
            try
            {
                var handler = new SignedHttpRequestHandlerPublic();
                var signedHttpRequestCreationData = theoryData.BuildSignedHttpRequestCreationData();

                handler.AddQClaimPublic(theoryData.Payload, signedHttpRequestCreationData);
                var payload = JObject.Parse(handler.ConvertToJsonPublic(theoryData.Payload));

                if (!payload.ContainsKey(theoryData.ExpectedClaim))
                    context.AddDiff($"Payload doesn't contain the claim '{theoryData.ExpectedClaim}'");

                if (!IdentityComparer.AreEqual(payload.Value<JArray>(theoryData.ExpectedClaim).ToString(Formatting.None), theoryData.ExpectedClaimValue))
                    context.AddDiff($"Value of '{theoryData.ExpectedClaim}' claim is '{payload.Value<JArray>(theoryData.ExpectedClaim).ToString(Formatting.None)}', but expected value was '{theoryData.ExpectedClaimValue}'");

                theoryData.ExpectedException.ProcessNoException(context);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<CreateSignedHttpRequestTheoryData> CreateQClaimTheoryData
        {
            get
            {
                return new TheoryData<CreateSignedHttpRequestTheoryData>
                {
                    new CreateSignedHttpRequestTheoryData
                    {
                        First = true,
                        ExpectedClaim = PopConstants.SignedHttpRequest.ClaimTypes.Q,
                        ExpectedClaimValue = $"[[\"queryParam1\"],\"{CalculateBase64UrlEncodedHash("queryParam1=value1")}\"]",
                        HttpRequestUri = new Uri("https://www.contoso.com/path1?queryParam1=value1"),
                        TestId = "ValidQ1",
                    },
                    new CreateSignedHttpRequestTheoryData
                    {
                        ExpectedClaim = PopConstants.SignedHttpRequest.ClaimTypes.Q,
                        ExpectedClaimValue = $"[[\"queryParam1\",\"queryParam2\"],\"{CalculateBase64UrlEncodedHash("queryParam1=value1&queryParam2=value2")}\"]",
                        HttpRequestUri = new Uri("https://www.contoso.com/path1?queryParam1=value1&queryParam2=value2"),
                        TestId = "ValidQ2",
                    },
                    new CreateSignedHttpRequestTheoryData
                    {
                        ExpectedClaim = PopConstants.SignedHttpRequest.ClaimTypes.Q,
                        ExpectedClaimValue = $"[[\"queryParam1\",\"queryParam2\"],\"{CalculateBase64UrlEncodedHash("queryParam1=value1&queryParam2=value2")}\"]",
                        HttpRequestUri = new Uri("https://www.contoso.com/path1?&queryParam1=value1&queryParam2=value2"),
                        TestId = "ValidQ3",
                    },
                    new CreateSignedHttpRequestTheoryData
                    {
                        ExpectedClaim = PopConstants.SignedHttpRequest.ClaimTypes.Q,
                        ExpectedClaimValue = $"[[\"query%20Param1\"],\"{CalculateBase64UrlEncodedHash("query%20Param1=value1")}\"]",
                        HttpRequestUri = new Uri("https://www.contoso.com/path1?query Param1=value1"),
                        TestId = "ValidQ4",
                    },
                    new CreateSignedHttpRequestTheoryData
                    {
                        ExpectedClaim = PopConstants.SignedHttpRequest.ClaimTypes.Q,
                        ExpectedClaimValue = $"[[\"query%20Param1%20\"],\"{CalculateBase64UrlEncodedHash("query%20Param1%20=value1%20")}\"]",
                        HttpRequestUri = new Uri("https://www.contoso.com/path1?query Param1 =value1%20"),
                        TestId = "ValidQ5",
                    },
                    new CreateSignedHttpRequestTheoryData
                    {
                        ExpectedClaim = PopConstants.SignedHttpRequest.ClaimTypes.Q,
                        ExpectedClaimValue = $"[[\"queryParam1\"],\"{CalculateBase64UrlEncodedHash("queryParam1=value1")}\"]",
                        HttpRequestUri = new Uri("https://www.contoso.com/path1?&queryParam1=value1&query=Param2=value2"),
                        TestId = "ValidQ6",
                    },
                    new CreateSignedHttpRequestTheoryData
                    {
                        ExpectedClaim = PopConstants.SignedHttpRequest.ClaimTypes.Q,
                        ExpectedClaimValue = $"[[],\"{CalculateBase64UrlEncodedHash("")}\"]",
                        HttpRequestUri = new Uri("https://www.contoso.com/path1"),
                        TestId = "ValidNoQueryParams1",
                    },
                    new CreateSignedHttpRequestTheoryData
                    {
                        ExpectedClaim = PopConstants.SignedHttpRequest.ClaimTypes.Q,
                        ExpectedClaimValue = $"[[],\"{CalculateBase64UrlEncodedHash("")}\"]",
                        HttpRequestUri = new Uri("https://www.contoso.com/path1&"),
                        TestId = "ValidNoQueryParams2",
                    },
                    new CreateSignedHttpRequestTheoryData
                    {
                        ExpectedClaim = PopConstants.SignedHttpRequest.ClaimTypes.Q,
                        ExpectedClaimValue = $"[[],\"{CalculateBase64UrlEncodedHash("")}\"]",
                        HttpRequestUri = new Uri("https://www.contoso.com/path1&t"),
                        TestId = "ValidNoQueryParams3",
                    },
                    new CreateSignedHttpRequestTheoryData
                    {
                        ExpectedClaim = PopConstants.SignedHttpRequest.ClaimTypes.Q,
                        ExpectedClaimValue = $"[[],\"{CalculateBase64UrlEncodedHash("")}\"]",
                        HttpRequestUri = new Uri("https://www.contoso.com/path1&t="),
                        TestId = "ValidNoQueryParams4",
                    },
                    new CreateSignedHttpRequestTheoryData
                    {
                        ExpectedClaim = PopConstants.SignedHttpRequest.ClaimTypes.Q,
                        ExpectedClaimValue = $"[[\"queryParam1\"],\"{CalculateBase64UrlEncodedHash("queryParam1=value1")}\"]",
                        HttpRequestUri = new Uri("https://www.contoso.com/path1?queryParam1=value1&repeated=repeated1&repeated=repeate2"),
                        TestId = "ValidRepeatedQ1",
                    },
                    new CreateSignedHttpRequestTheoryData
                    {
                        ExpectedClaim = PopConstants.SignedHttpRequest.ClaimTypes.Q,
                        ExpectedClaimValue = $"[[\"queryParam1\"],\"{CalculateBase64UrlEncodedHash("queryParam1=value1")}\"]",
                        HttpRequestUri = new Uri("https://www.contoso.com/path1?&repeated=repeated1&queryParam1=value1&repeated=repeate2"),
                        TestId = "ValidRepeatedQ2",
                    },
                    new CreateSignedHttpRequestTheoryData
                    {
                        ExpectedClaim = PopConstants.SignedHttpRequest.ClaimTypes.Q,
                        ExpectedClaimValue = $"[[\"queryParam1\"],\"{CalculateBase64UrlEncodedHash("queryParam1=value1")}\"]",
                        HttpRequestUri = new Uri("https://www.contoso.com/path1?&repeated=repeated1&repeated=repeate2&queryParam1=value1"),
                        TestId = "ValidRepeatedQ3",
                    },
                    new CreateSignedHttpRequestTheoryData
                    {
                        ExpectedClaim = PopConstants.SignedHttpRequest.ClaimTypes.Q,
                        ExpectedClaimValue = $"[[\"queryParam1\"],\"{CalculateBase64UrlEncodedHash("queryParam1=value1")}\"]",
                        HttpRequestUri = new Uri("https://www.contoso.com/path1?&repeated=repeated1&repeated=repeate2&queryParam1=value1&repeated=repeate3"),
                        TestId = "ValidRepeatedQ4",
                    },
                    new CreateSignedHttpRequestTheoryData
                    {
                        ExpectedClaim = PopConstants.SignedHttpRequest.ClaimTypes.Q,
                        ExpectedClaimValue = $"[[],\"{CalculateBase64UrlEncodedHash("")}\"]",
                        HttpRequestUri = new Uri("https://www.contoso.com/path1?&repeated=repeated1&repeated=repeate2"),
                        TestId = "RepeatedQEmpty",
                    },
                    new CreateSignedHttpRequestTheoryData
                    {
                        ExpectedClaim = PopConstants.SignedHttpRequest.ClaimTypes.Q,
                        ExpectedClaimValue = $"[[\"queryParam1\"],\"{CalculateBase64UrlEncodedHash("queryParam1=value1")}\"]",
                        HttpRequestUri = new Uri("/relativePath?queryParam1=value1", UriKind.Relative),
                        TestId = "ValidRelativeUri",
                    },
                    new CreateSignedHttpRequestTheoryData
                    {
                        Payload = null,
                        ExpectedException = ExpectedException.ArgumentNullException(),
                        TestId = "NullPayload",
                    },
                    new CreateSignedHttpRequestTheoryData
                    {
                        HttpRequestUri = null,
                        ExpectedException = ExpectedException.ArgumentNullException(),
                        TestId = "NullUri",
                    },
                };
            }
        }

        [Theory, MemberData(nameof(CreateHClaimTheoryData))]
        public void CreateHClaim(CreateSignedHttpRequestTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.CreateHClaim", theoryData);
            try
            {
                var handler = new SignedHttpRequestHandlerPublic();
                var signedHttpRequestCreationData = theoryData.BuildSignedHttpRequestCreationData();

                handler.AddHClaimPublic(theoryData.Payload, signedHttpRequestCreationData);
                var payload = JObject.Parse(handler.ConvertToJsonPublic(theoryData.Payload));

                if (!payload.ContainsKey(theoryData.ExpectedClaim))
                    context.AddDiff($"Payload doesn't contain the claim '{theoryData.ExpectedClaim}'");

                if (!IdentityComparer.AreEqual(payload.Value<JArray>(theoryData.ExpectedClaim).ToString(Formatting.None), theoryData.ExpectedClaimValue))
                    context.AddDiff($"Value of '{theoryData.ExpectedClaim}' claim is '{payload.Value<JArray>(theoryData.ExpectedClaim).ToString(Formatting.None)}', but expected value was '{theoryData.ExpectedClaimValue}'");

                theoryData.ExpectedException.ProcessNoException(context);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<CreateSignedHttpRequestTheoryData> CreateHClaimTheoryData
        {
            get
            {
                return new TheoryData<CreateSignedHttpRequestTheoryData>
                {
                    new CreateSignedHttpRequestTheoryData
                    {
                        First = true,
                        ExpectedClaim = PopConstants.SignedHttpRequest.ClaimTypes.H,
                        ExpectedClaimValue = $"[[\"headername1\"],\"{CalculateBase64UrlEncodedHash("headername1: headerValue1")}\"]",
                        HttpRequestHeaders = new Dictionary<string, IEnumerable<string>>()
                        {
                            { "headerName1" , new List<string> { "headerValue1" } }
                        },
                        TestId = "ValidH1",
                    },
                    new CreateSignedHttpRequestTheoryData
                    {
                        ExpectedClaim = PopConstants.SignedHttpRequest.ClaimTypes.H,
                        ExpectedClaimValue = $"[[\"headername1\",\"headername2\"],\"{CalculateBase64UrlEncodedHash("headername1: headerValue1\nheadername2: headerValue2")}\"]",
                        HttpRequestHeaders = new Dictionary<string, IEnumerable<string>>()
                        {
                            { "headerName1" , new List<string> { "headerValue1" } },
                            { "headerName2" , new List<string> { "headerValue2" } },
                        },
                        TestId = "ValidH2",
                    },
                    new CreateSignedHttpRequestTheoryData
                    {
                        ExpectedClaim = PopConstants.SignedHttpRequest.ClaimTypes.H,
                        ExpectedClaimValue = $"[[\"headername1\",\"headername2\",\"headername3\"],\"{CalculateBase64UrlEncodedHash("headername1: headerValue1\nheadername2: headerValue2\nheadername3: headerValue3")}\"]",
                        HttpRequestHeaders = new Dictionary<string, IEnumerable<string>>()
                        {
                            { "headerName1" , new List<string> { "headerValue1" } },
                            { "headerName2" , new List<string> { "headerValue2" } },
                            { "headerName3" , new List<string> { "headerValue3" } },
                        },
                        TestId = "ValidH3",
                    },
                    new CreateSignedHttpRequestTheoryData
                    {
                        ExpectedClaim = PopConstants.SignedHttpRequest.ClaimTypes.H,
                        ExpectedClaimValue = $"[[\"header name1\"],\"{CalculateBase64UrlEncodedHash("header name1: headerValue1")}\"]",
                        HttpRequestHeaders = new Dictionary<string, IEnumerable<string>>()
                        {
                            { "header Name1" , new List<string> { "headerValue1" } }
                        },
                        TestId = "ValidH4",
                    },
                    new CreateSignedHttpRequestTheoryData
                    {
                        ExpectedClaim = PopConstants.SignedHttpRequest.ClaimTypes.H,
                        ExpectedClaimValue = $"[[],\"{CalculateBase64UrlEncodedHash("")}\"]",
                        HttpRequestHeaders = new Dictionary<string, IEnumerable<string>>()
                        {
                            { "" , new List<string> { "headerValue1" } }
                        },
                        TestId = "ValidH5",
                    },
                    new CreateSignedHttpRequestTheoryData
                    {
                        ExpectedClaim = PopConstants.SignedHttpRequest.ClaimTypes.H,
                        ExpectedClaimValue = $"[[],\"{CalculateBase64UrlEncodedHash("")}\"]",
                        HttpRequestHeaders = new Dictionary<string, IEnumerable<string>>()
                        {
                            { "h1" , new List<string> { "" } }
                        },
                        TestId = "ValidH6",
                    },
                    new CreateSignedHttpRequestTheoryData
                    {
                        ExpectedClaim = PopConstants.SignedHttpRequest.ClaimTypes.H,
                        ExpectedClaimValue = $"[[\"headername1\"],\"{CalculateBase64UrlEncodedHash("headername1: headerValue1")}\"]",
                        HttpRequestHeaders = new Dictionary<string, IEnumerable<string>>()
                        {
                            { "headerName1" , new List<string> { "headerValue1" } },
                            { PopConstants.AuthorizationHeader , new List<string> { "exyxz..." } },
                        },
                        TestId = "ValidH7",
                    },
                    new CreateSignedHttpRequestTheoryData
                    {
                        ExpectedClaim = PopConstants.SignedHttpRequest.ClaimTypes.H,
                        ExpectedClaimValue = $"[[\"headername1\"],\"{CalculateBase64UrlEncodedHash("headername1: headerValue1")}\"]",
                        HttpRequestHeaders = new Dictionary<string, IEnumerable<string>>()
                        {
                            { "headerName1" , new List<string> { "headerValue1" } }
                        },
                        TestId = "NoHeaders",
                    },
                    new CreateSignedHttpRequestTheoryData
                    {
                        ExpectedClaim = PopConstants.SignedHttpRequest.ClaimTypes.H,
                        ExpectedClaimValue = $"[[\"headername1\"],\"{CalculateBase64UrlEncodedHash("headername1: headerValue1")}\"]",
                        HttpRequestHeaders = new Dictionary<string, IEnumerable<string>>()
                        {
                            { "headerName1" , new List<string> { "headerValue1" } },
                            { "headerName2" , new List<string> { "headerValue2", "headerValue10" } },
                        },
                        TestId = "ValidRepeatedH1",
                    },
                    new CreateSignedHttpRequestTheoryData
                    {
                        ExpectedClaim = PopConstants.SignedHttpRequest.ClaimTypes.H,
                        ExpectedClaimValue = $"[[\"headername1\"],\"{CalculateBase64UrlEncodedHash("headername1: headerValue1")}\"]",
                        HttpRequestHeaders = new Dictionary<string, IEnumerable<string>>()
                        {
                            { "headerName2" , new List<string> { "headerValue2", "headerValue10" } },
                            { "headerName1" , new List<string> { "headerValue1" } },
                        },
                        TestId = "ValidRepeatedH2",
                    },
                    new CreateSignedHttpRequestTheoryData
                    {
                        ExpectedClaim = PopConstants.SignedHttpRequest.ClaimTypes.H,
                        ExpectedClaimValue = $"[[],\"{CalculateBase64UrlEncodedHash("")}\"]",
                        HttpRequestHeaders = new Dictionary<string, IEnumerable<string>>()
                        {
                            { "headerName2" , new List<string> { "headerValue2", "headerValue10" } },
                        },
                        TestId = "ValidRepeatedH3",
                    },
                    new CreateSignedHttpRequestTheoryData
                    {
                        ExpectedClaim = PopConstants.SignedHttpRequest.ClaimTypes.H,
                        ExpectedClaimValue = $"[[\"headername1\"],\"{CalculateBase64UrlEncodedHash("headername1: headerValue1")}\"]",
                        HttpRequestHeaders = new Dictionary<string, IEnumerable<string>>()
                        {
                            { "HeaDerName2" , new List<string> { "headerValue2" } },
                            { "headername2" , new List<string> { "headerValue10" } },
                            { "headerName1" , new List<string> { "headerValue1" } },
                        },
                        TestId = "ValidRepeatedH4",
                    },
                    new CreateSignedHttpRequestTheoryData
                    {
                        ExpectedClaim = PopConstants.SignedHttpRequest.ClaimTypes.H,
                        ExpectedClaimValue = $"[[\"headername1\"],\"{CalculateBase64UrlEncodedHash("headername1: headerValue1")}\"]",
                        HttpRequestHeaders = new Dictionary<string, IEnumerable<string>>()
                        {
                            { "HeaDerName2" , new List<string> { "headerValue2" } },
                            { "headername2" , new List<string> { "headerValue10" } },
                            { "headerName1" , new List<string> { "headerValue1" } },
                            { "HEADERNAME2" , new List<string> { "headerValue22" } },
                        },
                        TestId = "ValidRepeatedH5",
                    },
                    new CreateSignedHttpRequestTheoryData
                    {
                        ExpectedClaim = PopConstants.SignedHttpRequest.ClaimTypes.H,
                        ExpectedClaimValue = $"[[],\"{CalculateBase64UrlEncodedHash("")}\"]",
                        HttpRequestHeaders = new Dictionary<string, IEnumerable<string>>()
                        {
                            { "headerName1" , new List<string> { "headerValue1", "headerValue10" } },
                        },
                        TestId = "ValidRepeatedH6",
                    },
                    new CreateSignedHttpRequestTheoryData
                    {
                        ExpectedClaim = PopConstants.SignedHttpRequest.ClaimTypes.H,
                        ExpectedClaimValue = $"[[],\"{CalculateBase64UrlEncodedHash("")}\"]",
                        HttpRequestHeaders = new Dictionary<string, IEnumerable<string>>(),
                        TestId = "EmptyHeaders",
                    },
                    new CreateSignedHttpRequestTheoryData
                    {
                        ExpectedClaim = PopConstants.SignedHttpRequest.ClaimTypes.H,
                        HttpRequestHeaders = null,
                        ExpectedException = ExpectedException.ArgumentNullException(),
                        TestId = "NullHeaders",
                    },
                    new CreateSignedHttpRequestTheoryData
                    {
                        Payload = null,
                        ExpectedException = ExpectedException.ArgumentNullException(),
                        TestId = "NullPayload",
                    },
                };
            }
        }

        [Theory, MemberData(nameof(CreateBClaimTheoryData))]
        public void CreateBClaim(CreateSignedHttpRequestTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.CreateBClaim", theoryData);
            try
            {
                var handler = new SignedHttpRequestHandlerPublic();
                var signedHttpRequestCreationData = theoryData.BuildSignedHttpRequestCreationData();

                handler.AddBClaimPublic(theoryData.Payload, signedHttpRequestCreationData);
                var payload = JObject.Parse(handler.ConvertToJsonPublic(theoryData.Payload));

                if (!payload.ContainsKey(theoryData.ExpectedClaim))
                    context.AddDiff($"Payload doesn't contain the claim '{theoryData.ExpectedClaim}'");

                if (!IdentityComparer.AreEqual(payload.Value<string>(theoryData.ExpectedClaim), theoryData.ExpectedClaimValue))
                    context.AddDiff($"Value of '{theoryData.ExpectedClaim}' claim is '{payload.Value<string>(theoryData.ExpectedClaim)}', but expected value was '{theoryData.ExpectedClaimValue}'");

                theoryData.ExpectedException.ProcessNoException(context);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<CreateSignedHttpRequestTheoryData> CreateBClaimTheoryData
        {
            get
            {
                return new TheoryData<CreateSignedHttpRequestTheoryData>
                {
                    new CreateSignedHttpRequestTheoryData
                    {
                        First = true,
                        ExpectedClaim = PopConstants.SignedHttpRequest.ClaimTypes.B,
                        ExpectedClaimValue = CalculateBase64UrlEncodedHash(Encoding.UTF8.GetBytes("abcd")),
                        HttpRequestBody = Encoding.UTF8.GetBytes("abcd"),
                        TestId = "ValidB1",
                    },
                    new CreateSignedHttpRequestTheoryData
                    {
                        ExpectedClaim = PopConstants.SignedHttpRequest.ClaimTypes.B,
                        ExpectedClaimValue = CalculateBase64UrlEncodedHash(Encoding.UTF8.GetBytes("")),
                        HttpRequestBody = new byte[0],
                        TestId = "ValidB2",
                    },
                    new CreateSignedHttpRequestTheoryData
                    {
                        ExpectedClaim = PopConstants.SignedHttpRequest.ClaimTypes.B,
                        ExpectedClaimValue = CalculateBase64UrlEncodedHash(Encoding.UTF8.GetBytes("")),
                        HttpRequestBody = null,
                        TestId = "NullBytes",
                    },
                    new CreateSignedHttpRequestTheoryData
                    {
                        Payload = null,
                        ExpectedException = ExpectedException.ArgumentNullException(),
                        TestId = "NullPayload",
                    },
                };
            }
        }

        [Theory, MemberData(nameof(CreateNonceClaimTheoryData))]
        public void CreateNonceClaim(CreateSignedHttpRequestTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.CreateNonceClaim", theoryData);
            try
            {
                var handler = new SignedHttpRequestHandlerPublic();
                var signedHttpRequestCreationData = theoryData.BuildSignedHttpRequestCreationData();

                handler.AddNonceClaimPublic(theoryData.Payload, signedHttpRequestCreationData);
                var payload = JObject.Parse(handler.ConvertToJsonPublic(theoryData.Payload));

                if (!payload.ContainsKey(theoryData.ExpectedClaim))
                    context.AddDiff($"Payload doesn't contain the claim '{theoryData.ExpectedClaim}'");

                if (theoryData.SignedHttpRequestCreationPolicy.CustomNonceCreator != null)
                {
                    if (!IdentityComparer.AreEqual(payload.Value<string>(theoryData.ExpectedClaim), theoryData.ExpectedClaimValue))
                        context.AddDiff($"Value of '{theoryData.ExpectedClaim}' claim is '{payload.Value<string>(theoryData.ExpectedClaim)}', but expected value was '{theoryData.ExpectedClaimValue}'");
                }

                theoryData.ExpectedException.ProcessNoException(context);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<CreateSignedHttpRequestTheoryData> CreateNonceClaimTheoryData
        {
            get
            {
                return new TheoryData<CreateSignedHttpRequestTheoryData>
                {
                    new CreateSignedHttpRequestTheoryData
                    {
                        First = true,
                        ExpectedClaim = PopConstants.SignedHttpRequest.ClaimTypes.Nonce,
                        TestId = "ValidDefaultNonce",
                    },
                    new CreateSignedHttpRequestTheoryData
                    {
                        ExpectedClaim = "customNonce",
                        ExpectedClaimValue = "customNonceValue",
                        SignedHttpRequestCreationPolicy = new SignedHttpRequestCreationPolicy()
                        {
                            CustomNonceCreator = (IDictionary<string, object> payload, SignedHttpRequestCreationData signedHttpRequestCreationData) => payload.Add("customNonce", "customNonceValue"),
                        },
                        TestId = "ValidCustomNonce",
                    },
                    new CreateSignedHttpRequestTheoryData
                    {
                        Payload = null,
                        ExpectedException = ExpectedException.ArgumentNullException(),
                        TestId = "NullPayload",
                    },
                };
            }
        }

        [Theory, MemberData(nameof(CreateAdditionalClaimTheoryData))]
        public void CreateAdditionalClaim(CreateSignedHttpRequestTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.CreateAdditionalClaim", theoryData);
            try
            {
                var handler = new SignedHttpRequestHandlerPublic();
                var signedHttpRequestCreationData = theoryData.BuildSignedHttpRequestCreationData();

                var payloadString =  handler.CreateHttpRequestPayloadPublic(signedHttpRequestCreationData);
                var payload = JObject.Parse(payloadString);

                if (theoryData.SignedHttpRequestCreationPolicy.AdditionalClaimCreator != null)
                {
                    if (!payload.ContainsKey(theoryData.ExpectedClaim))
                        context.AddDiff($"Payload doesn't contain the claim '{theoryData.ExpectedClaim}'");

                    if (!IdentityComparer.AreEqual(payload.Value<string>(theoryData.ExpectedClaim), theoryData.ExpectedClaimValue))
                        context.AddDiff($"Value of '{theoryData.ExpectedClaim}' claim is '{payload.Value<string>(theoryData.ExpectedClaim)}', but expected value was '{theoryData.ExpectedClaimValue}'");
                }
                else
                {
                    if (payload.ContainsKey(theoryData.ExpectedClaim))
                        context.AddDiff($"Payload shouldn't contain the claim '{theoryData.ExpectedClaim}'");
                }

                theoryData.ExpectedException.ProcessNoException(context);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<CreateSignedHttpRequestTheoryData> CreateAdditionalClaimTheoryData
        {
            get
            {
                return new TheoryData<CreateSignedHttpRequestTheoryData>
                {
                    new CreateSignedHttpRequestTheoryData
                    {
                        First = true,
                        ExpectedClaim = "customClaim",
                        ExpectedClaimValue = "customClaimValue",
                        SignedHttpRequestCreationPolicy = new SignedHttpRequestCreationPolicy()
                        {
                            CreateU = false,
                            CreateM = false,
                            CreateP = false,
                            AdditionalClaimCreator = (IDictionary<string, object> payload, SignedHttpRequestCreationData signedHttpRequestCreationData) => payload.Add("customClaim", "customClaimValue"),
                        },
                        TestId = "ValidAdditionalClaim",
                    },
                    new CreateSignedHttpRequestTheoryData
                    {
                        ExpectedClaim = "customClaim",
                        ExpectedClaimValue = "customClaimValue",
                        SignedHttpRequestCreationPolicy = new SignedHttpRequestCreationPolicy()
                        {
                            CreateU = false,
                            CreateM = false,
                            CreateP = false,
                        },
                        TestId = "DelegateNotSet",
                    },
                    new CreateSignedHttpRequestTheoryData
                    {
                        Payload = null,
                        ExpectedException = ExpectedException.ArgumentNullException(),
                        TestId = "NullPayload",
                    },
                };
            }
        }

        private static string CalculateBase64UrlEncodedHash(string data)
        {
            return CalculateBase64UrlEncodedHash(Encoding.UTF8.GetBytes(data));
        }

        private static string CalculateBase64UrlEncodedHash(byte[] bytes)
        {
            using (var hash = SHA256.Create())
            {
                var hashedBytes = hash.ComputeHash(bytes);
                return Base64UrlEncoder.Encode(hashedBytes);
            }
        }
    }

    public class CreateSignedHttpRequestTheoryData : TheoryDataBase
    {
        public SignedHttpRequestCreationData BuildSignedHttpRequestCreationData()
        {
            var httpRequestData = new HttpRequestData()
            {
                Body = HttpRequestBody,
                Uri = HttpRequestUri,
                Method = HttpRequestMethod,
                Headers = HttpRequestHeaders
            };

            var callContext = CallContext;
            if (callContext.PropertyBag == null)
                callContext.PropertyBag = new Dictionary<string, object>() { { "testId", TestId } };
            else
                callContext.PropertyBag.Add("testId", TestId);

            return new SignedHttpRequestCreationData(Token, httpRequestData, SigningCredentials, SignedHttpRequestCreationPolicy, callContext);
        }

        public CallContext CallContext { get; set; } = CallContext.Default;

        public object ExpectedClaimValue { get; set; }

        public string ExpectedClaim { get; set; }

        public List<string> ExpectedPayloadClaims { get; set; }

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

        public SigningCredentials SigningCredentials { get; set; } = Default.AsymmetricSigningCredentials;

        public string Token { get; set; } = ReferenceTokens.JWSWithDifferentTyp;

        public string HeaderString { get; set; }

        public string PayloadString { get; set; }
    }
}

#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
