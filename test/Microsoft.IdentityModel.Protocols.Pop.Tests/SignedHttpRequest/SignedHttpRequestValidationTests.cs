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
using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography;
using System.Text;
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
    public class SignedHttpRequestValidationTests
    {
        private readonly static string _encodedTokenHelper = "eyJhbGciOiJSUzI1NiIsImtpZCI6IlJzYVNlY3VyaXR5S2V5XzIwNDgiLCJ0eXAiOiJwb3AifQ.eyJhdCI6eyJlbWFpbCI6IkJvYkBjb250b3NvLmNvbSIsImdpdmVuX25hbWUiOiJCb2IiLCJpc3MiOiJodHRwOi8vRGVmYXVsdC5Jc3N1ZXIuY29tIiwiYXVkIjoiaHR0cDovL0RlZmF1bHQuQXVkaWVuY2UuY29tIiwiaWF0IjoiMTQ4OTc3NTYxNyIsIm5iZiI6IjE0ODk3NzU2MTciLCJleHAiOiIxNjE2MDA2MDE3IiwiY25mIjp7Imp3ayI6eyJrdHkiOiJSU0EiLCJuIjoiNitGckZrdC9UQnlRL0w1ZDdvcis5UFZBb3dwc3d4VWUzZEplWUZUWTBMZ3E3ektJNU9RNVJuU3JJMFQ5eXJmblJ6RTlvT2RkNHptVmo5dHhWTEkreXlTdmluQXUzeVFEUW91MkdhNDJNTC8rSzRKcmQ1Y2xNVVBSR01iWGRWNVJsOXp6QjBzMkpvWkplZHVhNWR3b1F3MEdrUzVaOFlBWEJFelVMcnVwMDZmbkI1bjZ4NXIyeTFDLzhFYnA1Y3lFNEJqczdXNjhyVWx5SWx4MWx6WXZha3hTbmhVeFNzang3dS9tSWR5d3lHZmdpVDN0dzBGc1d2a2kvS1l1ckFQUjFCU01YaEN6elpUa01XS0U4SWFMa2hhdXc1TWR4b2p4eUJWdU5ZK0ovZWxxK0hnSi9kWks2Zzd2TU52WHoyL3ZUK1N5a0lrendpRDllU0k5VVdmc2p3PT0iLCJlIjoiQVFBQiIsImFsZyI6IlJTMjU2Iiwia2lkIjoiUnNhU2VjdXJpdHlLZXlfMjA0OCJ9fX0sIm0iOiJHRVQiLCJ1Ijoid3d3LmNvbnRvc28uY29tIiwicCI6Ii9wYXRoMSIsInEiOiJbW1wiYlwiLFwiYVwiLFwiY1wiXSxcInU0TGdrR1VXaFA5TXNLckVqQTRkaXpJbGxEWGx1RGt1NlpxQ2V5dVItSllcIl0iLCJoIjoiW1tcImNvbnRlbnQtdHlwZVwiLFwiZXRhZ1wiXSxcIlA2ejVYTjR0VHpIa2Z3ZTNYTzFZdlZVSXVyU3VodmhfVUcxME5fai1hR3NcIl0iLCJiIjoiWkstTzJnekhqcHNDR3BlZDZzVUwyRU0yMFo5VC11RjA3TENHTUE4OFVGdyIsIm5vbmNlIjoiODFkYTQ5MGY0NmMzNDk0ZWJhOGM2ZTI1YTQ1YTRkMGYiLCJ0cyI6MTU2OTk0NDc2OSwiZXhwIjoxNTY5OTczNTc4LjAsImlhdCI6MTU2OTk2OTk3OCwibmJmIjoxNTY5OTY5OTc4fQ.OiLM-S_Da8gwKw3dxXI-4TMyH9JZuKCdJnr_1xyFg1UbhKe2kuWA9J6nBtuAWHXUxHpvwwHNYcEjB6eNMJFEHnAVwEvaMgJCmI0dG6xof201riSKqflFJxh2fq7z2clReWpLLmP0o1S1LGSx74g5cubl90ivQ7MoYPeyIMoSTfGwsTGXKAnf4MnCIt3Ykp0KbTj6WHnS1LmtSCTBGXslV7jD28ikjF3w5Xk2Nv6WmUJAYNhGC3fiUnzqt3buiyynhF4sXbYxKDLYPeUWH-oZVEFuaGC2nnTA_5-aS0yHPmcj-CDRanHAZA9Y-UFMyFm9oO-QffHc-ZL8mcIfx-Kmfg";

        [Theory, MemberData(nameof(ValidateTsClaimTheoryData))]
        public void ValidateTsClaim(ValidateSignedHttpRequestTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.ValidateTsClaim", theoryData);
            try
            {
                var handler = new SignedHttpRequestHandlerPublic();
                var signedHttpRequestValidationData = theoryData.BuildSignedHttpRequestValidationData();
                handler.ValidateTsClaimPublic(theoryData.SignedHttpRequestToken, signedHttpRequestValidationData);
                theoryData.ExpectedException.ProcessNoException(context);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<ValidateSignedHttpRequestTheoryData> ValidateTsClaimTheoryData
        {
            get
            {
                return new TheoryData<ValidateSignedHttpRequestTheoryData>
                {
                    new ValidateSignedHttpRequestTheoryData
                    {
                        First = true,
                        SignedHttpRequestToken = ReplaceOrAddPropertyAndCreateSignedHttpRequest(new JProperty(PopConstants.SignedHttpRequest.ClaimTypes.Ts, (long)(DateTime.UtcNow - EpochTime.UnixEpoch).TotalSeconds) ),
                        TestId = "ValidTs",
                    },
                    new ValidateSignedHttpRequestTheoryData
                    {
                        SignedHttpRequestToken = ReplaceOrAddPropertyAndCreateSignedHttpRequest(new JProperty(PopConstants.SignedHttpRequest.ClaimTypes.Ts, (long)(DateTime.UtcNow.AddHours(1) - EpochTime.UnixEpoch).TotalSeconds) ),
                        TestId = "ValidTs2",
                    },
                    new ValidateSignedHttpRequestTheoryData
                    {
                        SignedHttpRequestToken = ReplaceOrAddPropertyAndCreateSignedHttpRequest(new JProperty(PopConstants.SignedHttpRequest.ClaimTypes.Ts, (long)(DateTime.UtcNow.AddMinutes(-6) - EpochTime.UnixEpoch).TotalSeconds) ),
                        ExpectedException = new ExpectedException(typeof(SignedHttpRequestInvalidTsClaimException), "IDX23010"),
                        TestId = "Expired",
                    },
                    new ValidateSignedHttpRequestTheoryData
                    {
                        SignedHttpRequestToken = ReplaceOrAddPropertyAndCreateSignedHttpRequest(new JProperty(PopConstants.SignedHttpRequest.ClaimTypes.Ts, (DateTime.UtcNow- EpochTime.UnixEpoch).TotalSeconds.ToString())),
                        ExpectedException = new ExpectedException(typeof(SignedHttpRequestInvalidTsClaimException), "IDX23003"),
                        TestId = "InvalidNotLong",
                    },
                    new ValidateSignedHttpRequestTheoryData
                    {
                        SignedHttpRequestToken = ReplaceOrAddPropertyAndCreateSignedHttpRequest(new JProperty(PopConstants.SignedHttpRequest.ClaimTypes.Ts, null)),
                        ExpectedException = new ExpectedException(typeof(SignedHttpRequestInvalidTsClaimException), "IDX23003"),
                        TestId = "InvalidClaimNotPresent",
                    },
                    new ValidateSignedHttpRequestTheoryData
                    {
                        SignedHttpRequestToken = new JwtSecurityToken(_encodedTokenHelper),
                        ExpectedException = new ExpectedException(typeof(SignedHttpRequestValidationException), "IDX23031"),
                        TestId = "InvalidTokenType",
                    },
                    new ValidateSignedHttpRequestTheoryData
                    {
                        SignedHttpRequestToken = null,
                        ExpectedException = ExpectedException.ArgumentNullException(),
                        TestId = "NullToken",
                    },
                };
            }
        }

        [Theory, MemberData(nameof(ValidateMClaimTheoryData))]
        public void ValidateMClaim(ValidateSignedHttpRequestTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.ValidateMClaim", theoryData);
            try
            {
                var handler = new SignedHttpRequestHandlerPublic();
                var signedHttpRequestValidationData = theoryData.BuildSignedHttpRequestValidationData();
                handler.ValidateMClaimPublic(theoryData.SignedHttpRequestToken, signedHttpRequestValidationData);
                theoryData.ExpectedException.ProcessNoException(context);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<ValidateSignedHttpRequestTheoryData> ValidateMClaimTheoryData
        {
            get
            {
                return new TheoryData<ValidateSignedHttpRequestTheoryData>
                {
                    new ValidateSignedHttpRequestTheoryData
                    {
                        First = true,
                        HttpRequestMethod = "GET",
                        SignedHttpRequestToken = ReplaceOrAddPropertyAndCreateSignedHttpRequest(new JProperty(PopConstants.SignedHttpRequest.ClaimTypes.M, "GET")),
                        TestId = "ValidM1",
                    },
                    new ValidateSignedHttpRequestTheoryData
                    {
                        HttpRequestMethod = "GET",
                        SignedHttpRequestToken = ReplaceOrAddPropertyAndCreateSignedHttpRequest(new JProperty(PopConstants.SignedHttpRequest.ClaimTypes.M, "get")),
                        TestId = "ValidM2",
                    },
                    new ValidateSignedHttpRequestTheoryData
                    {
                        HttpRequestMethod = " GET  ",
                        SignedHttpRequestToken = ReplaceOrAddPropertyAndCreateSignedHttpRequest(new JProperty(PopConstants.SignedHttpRequest.ClaimTypes.M, "  gEt     ")),
                        TestId = "ValidM3",
                    },
                    new ValidateSignedHttpRequestTheoryData
                    {
                        HttpRequestMethod = "POST",
                        SignedHttpRequestToken = ReplaceOrAddPropertyAndCreateSignedHttpRequest(new JProperty(PopConstants.SignedHttpRequest.ClaimTypes.M, "GET")),
                        ExpectedException = new ExpectedException(typeof(SignedHttpRequestInvalidMClaimException), "IDX23011"),
                        TestId = "InvalidMismatch",
                    },
                    new ValidateSignedHttpRequestTheoryData
                    {
                        HttpRequestMethod = "",
                        ExpectedException = ExpectedException.ArgumentNullException(),
                        TestId = "EmptyExpectedMethod",
                    },
                    new ValidateSignedHttpRequestTheoryData
                    {
                        HttpRequestMethod = null,
                        ExpectedException = ExpectedException.ArgumentNullException(),
                        TestId = "NullExpectedMethod",
                    },
                    new ValidateSignedHttpRequestTheoryData
                    {
                        HttpRequestMethod = "GET",
                        SignedHttpRequestToken = ReplaceOrAddPropertyAndCreateSignedHttpRequest(new JProperty(PopConstants.SignedHttpRequest.ClaimTypes.M, null)),
                        ExpectedException = new ExpectedException(typeof(SignedHttpRequestInvalidMClaimException), "IDX23003"),
                        TestId = "InvalidClaimNotPresent",
                    },
                    new ValidateSignedHttpRequestTheoryData
                    {
                        HttpRequestMethod = "GET",
                        SignedHttpRequestToken = new JwtSecurityToken(_encodedTokenHelper),
                        ExpectedException = new ExpectedException(typeof(SignedHttpRequestValidationException), "IDX23031"),
                        TestId = "InvalidTokenType",
                    },
                    new ValidateSignedHttpRequestTheoryData
                    {
                        SignedHttpRequestToken = null,
                        ExpectedException = ExpectedException.ArgumentNullException(),
                        TestId = "NullToken",
                    },
                };
            }
        }

        [Theory, MemberData(nameof(ValidateUClaimTheoryData))]
        public void ValidateUClaim(ValidateSignedHttpRequestTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.ValidateUClaim", theoryData);
            try
            {
                var handler = new SignedHttpRequestHandlerPublic();
                var signedHttpRequestValidationData = theoryData.BuildSignedHttpRequestValidationData();
                handler.ValidateUClaimPublic(theoryData.SignedHttpRequestToken, signedHttpRequestValidationData);
                theoryData.ExpectedException.ProcessNoException(context);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<ValidateSignedHttpRequestTheoryData> ValidateUClaimTheoryData
        {
            get
            {
                return new TheoryData<ValidateSignedHttpRequestTheoryData>
                {
                    new ValidateSignedHttpRequestTheoryData
                    {
                        First = true,
                        HttpRequestUri = new Uri("https://www.contoso.com"),
                        SignedHttpRequestToken = ReplaceOrAddPropertyAndCreateSignedHttpRequest(new JProperty(PopConstants.SignedHttpRequest.ClaimTypes.U, "www.contoso.com")),
                        TestId = "ValidU1",
                    },
                    new ValidateSignedHttpRequestTheoryData
                    {
                        HttpRequestUri = new Uri("https://www.contoso.com"),
                        SignedHttpRequestToken = ReplaceOrAddPropertyAndCreateSignedHttpRequest(new JProperty(PopConstants.SignedHttpRequest.ClaimTypes.U, "www.CONTOSO.com")),
                        TestId = "ValidU2",
                    },
                    new ValidateSignedHttpRequestTheoryData
                    {
                        HttpRequestUri = new Uri("https://www.contoso.com"),
                        SignedHttpRequestToken = ReplaceOrAddPropertyAndCreateSignedHttpRequest(new JProperty(PopConstants.SignedHttpRequest.ClaimTypes.U, "www.contoso.com:443")),
                        TestId = "ValidU3",
                    },
                    new ValidateSignedHttpRequestTheoryData
                    {
                        HttpRequestUri = new Uri("https://www.contoso.com:443"),
                        SignedHttpRequestToken = ReplaceOrAddPropertyAndCreateSignedHttpRequest(new JProperty(PopConstants.SignedHttpRequest.ClaimTypes.U, "www.contoso.com")),
                        TestId = "ValidU4",
                    },
                    new ValidateSignedHttpRequestTheoryData
                    {
                        HttpRequestUri = new Uri("https://www.contoso.com:443"),
                        SignedHttpRequestToken = ReplaceOrAddPropertyAndCreateSignedHttpRequest(new JProperty(PopConstants.SignedHttpRequest.ClaimTypes.U, "www.contoso.com:443")),
                        TestId = "ValidU5",
                    },
                    new ValidateSignedHttpRequestTheoryData
                    {
                        HttpRequestUri = new Uri("https://www.contoso.com"),
                        SignedHttpRequestToken = ReplaceOrAddPropertyAndCreateSignedHttpRequest(new JProperty(PopConstants.SignedHttpRequest.ClaimTypes.U, "www.contoso2.com")),
                        ExpectedException = new ExpectedException(typeof(SignedHttpRequestInvalidUClaimException), "IDX23012"),
                        TestId = "InvalidMismatch",
                    },
                    new ValidateSignedHttpRequestTheoryData
                    {
                        HttpRequestUri = new Uri("/path1", UriKind.Relative),
                        SignedHttpRequestToken = ReplaceOrAddPropertyAndCreateSignedHttpRequest(new JProperty(PopConstants.SignedHttpRequest.ClaimTypes.U, "www.contoso.com")),
                        ExpectedException = new ExpectedException(typeof(SignedHttpRequestInvalidUClaimException), "IDX23001"),
                        TestId = "InvalidRelativeUri",
                    },
                    new ValidateSignedHttpRequestTheoryData
                    {
                        HttpRequestUri = null,
                        ExpectedException = ExpectedException.ArgumentNullException(),
                        TestId = "NullUri",
                    },
                    new ValidateSignedHttpRequestTheoryData
                    {
                        HttpRequestUri = new Uri("https://www.contoso.com"),
                        SignedHttpRequestToken = ReplaceOrAddPropertyAndCreateSignedHttpRequest(new JProperty(PopConstants.SignedHttpRequest.ClaimTypes.U, null)),
                        ExpectedException = new ExpectedException(typeof(SignedHttpRequestInvalidUClaimException), "IDX23003"),
                        TestId = "InvalidClaimNotPresent",
                    },
                    new ValidateSignedHttpRequestTheoryData
                    {
                        HttpRequestUri = new Uri("https://www.contoso.com"),
                        SignedHttpRequestToken = new JwtSecurityToken(_encodedTokenHelper),
                        ExpectedException = new ExpectedException(typeof(SignedHttpRequestValidationException), "IDX23031"),
                        TestId = "InvalidTokenType",
                    },
                    new ValidateSignedHttpRequestTheoryData
                    {
                        SignedHttpRequestToken = null,
                        ExpectedException = ExpectedException.ArgumentNullException(),
                        TestId = "NullToken",
                    },
                };
            }
        }

        [Theory, MemberData(nameof(ValidatePClaimTheoryData))]
        public void ValidatePClaim(ValidateSignedHttpRequestTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.ValidatePClaim", theoryData);
            try
            {
                var handler = new SignedHttpRequestHandlerPublic();
                var signedHttpRequestValidationData = theoryData.BuildSignedHttpRequestValidationData();
                handler.ValidatePClaimPublic(theoryData.SignedHttpRequestToken, signedHttpRequestValidationData);
                theoryData.ExpectedException.ProcessNoException(context);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<ValidateSignedHttpRequestTheoryData> ValidatePClaimTheoryData
        {
            get
            {
                return new TheoryData<ValidateSignedHttpRequestTheoryData>
                {
                    new ValidateSignedHttpRequestTheoryData
                    {
                        First = true,
                        HttpRequestUri = new Uri("https://www.contoso.com/path1"),
                        SignedHttpRequestToken = ReplaceOrAddPropertyAndCreateSignedHttpRequest(new JProperty(PopConstants.SignedHttpRequest.ClaimTypes.P, "/path1")),
                        TestId = "ValidP1",
                    },
                    new ValidateSignedHttpRequestTheoryData
                    {
                        HttpRequestUri = new Uri("https://www.contoso.com/path1"),
                        SignedHttpRequestToken = ReplaceOrAddPropertyAndCreateSignedHttpRequest(new JProperty(PopConstants.SignedHttpRequest.ClaimTypes.P, "/path1/")),
                        TestId = "ValidP2",
                    },
                    new ValidateSignedHttpRequestTheoryData
                    {
                        HttpRequestUri = new Uri("https://www.contoso.com/path1"),
                        SignedHttpRequestToken = ReplaceOrAddPropertyAndCreateSignedHttpRequest(new JProperty(PopConstants.SignedHttpRequest.ClaimTypes.P, "path1")),
                        TestId = "ValidP3",
                    },
                    new ValidateSignedHttpRequestTheoryData
                    {
                        HttpRequestUri = new Uri("https://www.contoso.com/path1"),
                        SignedHttpRequestToken = ReplaceOrAddPropertyAndCreateSignedHttpRequest(new JProperty(PopConstants.SignedHttpRequest.ClaimTypes.P, "path1/")),
                        TestId = "ValidP4",
                    },
                    new ValidateSignedHttpRequestTheoryData
                    {
                        HttpRequestUri = new Uri("/path1", UriKind.Relative),
                        SignedHttpRequestToken = ReplaceOrAddPropertyAndCreateSignedHttpRequest(new JProperty(PopConstants.SignedHttpRequest.ClaimTypes.P, "/path1")),
                        TestId = "ValidP5",
                    },
                    new ValidateSignedHttpRequestTheoryData
                    {
                        HttpRequestUri = new Uri("https://www.contoso.com/pa th1"),
                        SignedHttpRequestToken = ReplaceOrAddPropertyAndCreateSignedHttpRequest(new JProperty(PopConstants.SignedHttpRequest.ClaimTypes.P, "/pa%20th1")),
                        TestId = "ValidP6",
                    },
                    new ValidateSignedHttpRequestTheoryData
                    {
                        HttpRequestUri = new Uri("https://www.contoso.com/path1/more/andmore"),
                        SignedHttpRequestToken = ReplaceOrAddPropertyAndCreateSignedHttpRequest(new JProperty(PopConstants.SignedHttpRequest.ClaimTypes.P, "/path1/more/andmore")),
                        TestId = "ValidP8",
                    },
                    new ValidateSignedHttpRequestTheoryData
                    {
                        HttpRequestUri = new Uri("https://www.contoso.com/path1/more/andmore"),
                        SignedHttpRequestToken = ReplaceOrAddPropertyAndCreateSignedHttpRequest(new JProperty(PopConstants.SignedHttpRequest.ClaimTypes.P, "/path1/more/andmore/")),
                        TestId = "ValidP9",
                    },
                    new ValidateSignedHttpRequestTheoryData
                    {
                        HttpRequestUri = new Uri("https://www.contoso.com/path1/more/andmore/"),
                        SignedHttpRequestToken = ReplaceOrAddPropertyAndCreateSignedHttpRequest(new JProperty(PopConstants.SignedHttpRequest.ClaimTypes.P, "/path1/more/andmore/")),
                        TestId = "ValidP10",
                    },
                    new ValidateSignedHttpRequestTheoryData
                    {
                        HttpRequestUri = new Uri("https://www.contoso.com/path1"),
                        SignedHttpRequestToken = ReplaceOrAddPropertyAndCreateSignedHttpRequest(new JProperty(PopConstants.SignedHttpRequest.ClaimTypes.P, "/path2")),
                        ExpectedException = new ExpectedException(typeof(SignedHttpRequestInvalidPClaimException), "IDX23011"),
                        TestId = "InvalidMismatch",
                    },
                    new ValidateSignedHttpRequestTheoryData
                    {
                        HttpRequestUri = null,
                        ExpectedException = ExpectedException.ArgumentNullException(),
                        TestId = "NullUri",
                    },
                    new ValidateSignedHttpRequestTheoryData
                    {
                        HttpRequestUri = new Uri("https://www.contoso.com"),
                        SignedHttpRequestToken = ReplaceOrAddPropertyAndCreateSignedHttpRequest(new JProperty(PopConstants.SignedHttpRequest.ClaimTypes.P, null)),
                        ExpectedException = new ExpectedException(typeof(SignedHttpRequestInvalidPClaimException), "IDX23003"),
                        TestId = "InvalidClaimNotPresent",
                    },
                    new ValidateSignedHttpRequestTheoryData
                    {
                        HttpRequestUri = new Uri("https://www.contoso.com/path1"),
                        SignedHttpRequestToken = new JwtSecurityToken(_encodedTokenHelper),
                        ExpectedException = new ExpectedException(typeof(SignedHttpRequestValidationException), "IDX23031"),
                        TestId = "InvalidTokenType",
                    },
                    new ValidateSignedHttpRequestTheoryData
                    {
                        SignedHttpRequestToken = null,
                        ExpectedException = ExpectedException.ArgumentNullException(),
                        TestId = "NullToken",
                    },
                };
            }
        }

        [Theory, MemberData(nameof(ValidateBClaimTheoryData))]
        public void ValidateBClaim(ValidateSignedHttpRequestTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.ValidateBClaim", theoryData);
            try
            {
                var handler = new SignedHttpRequestHandlerPublic();
                var signedHttpRequestValidationData = theoryData.BuildSignedHttpRequestValidationData();
                handler.ValidateBClaimPublic(theoryData.SignedHttpRequestToken, signedHttpRequestValidationData);
                theoryData.ExpectedException.ProcessNoException(context);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<ValidateSignedHttpRequestTheoryData> ValidateBClaimTheoryData
        {
            get
            {
                return new TheoryData<ValidateSignedHttpRequestTheoryData>
                {
                    new ValidateSignedHttpRequestTheoryData
                    {
                        First = true,
                        HttpRequestBody = Encoding.UTF8.GetBytes("abcd"),
                        SignedHttpRequestToken = ReplaceOrAddPropertyAndCreateSignedHttpRequest(new JProperty(PopConstants.SignedHttpRequest.ClaimTypes.B, CalculateBase64UrlEncodedHash("abcd"))),
                        TestId = "ValidB1",
                    },
                    new ValidateSignedHttpRequestTheoryData
                    {
                        HttpRequestBody = Encoding.UTF8.GetBytes("abcd"),
                        SignedHttpRequestToken = ReplaceOrAddPropertyAndCreateSignedHttpRequest(new JProperty(PopConstants.SignedHttpRequest.ClaimTypes.B, CalculateBase64UrlEncodedHash("aaaa"))),
                        ExpectedException = new ExpectedException(typeof(SignedHttpRequestInvalidBClaimException), "IDX23011"),
                        TestId = "InvalidMismatch",
                    },
                    new ValidateSignedHttpRequestTheoryData
                    {
                        HttpRequestBody = null,
                        SignedHttpRequestToken = ReplaceOrAddPropertyAndCreateSignedHttpRequest(new JProperty(PopConstants.SignedHttpRequest.ClaimTypes.B, CalculateBase64UrlEncodedHash(""))),
                        TestId = "NullBytesValid",
                    },
                    new ValidateSignedHttpRequestTheoryData
                    {
                        SignedHttpRequestToken = ReplaceOrAddPropertyAndCreateSignedHttpRequest(new JProperty(PopConstants.SignedHttpRequest.ClaimTypes.B, null)),
                        ExpectedException = new ExpectedException(typeof(SignedHttpRequestInvalidBClaimException), "IDX23003"),
                        TestId = "InvalidClaimNotPresent",
                    },
                    new ValidateSignedHttpRequestTheoryData
                    {
                        SignedHttpRequestToken = new JwtSecurityToken(_encodedTokenHelper),
                        ExpectedException = new ExpectedException(typeof(SignedHttpRequestValidationException), "IDX23031"),
                        TestId = "InvalidTokenType",
                    },
                    new ValidateSignedHttpRequestTheoryData
                    {
                        SignedHttpRequestToken = null,
                        ExpectedException = ExpectedException.ArgumentNullException(),
                        TestId = "NullToken",
                    },
                };
            }
        }

        internal static JsonWebToken ReplaceOrAddPropertyAndCreateSignedHttpRequest(JProperty newProperty)
        {
            JObject token = SignedHttpRequestTestUtils.SignedHttpRequestPayload;

            if (token.ContainsKey(newProperty.Name))
                token.Property(newProperty.Name).Remove();

            if (newProperty.Value != null)
                token.Add(newProperty);

            return new JsonWebToken(new JsonWebTokenHandler().CreateToken(token.ToString(Formatting.None), SignedHttpRequestTestUtils.SigningCredentials, new Dictionary<string, object>() { { System.IdentityModel.Tokens.Jwt.JwtHeaderParameterNames.Typ, PopConstants.SignedHttpRequest.TokenType } }));
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
    }

    public class ValidateSignedHttpRequestTheoryData : TheoryDataBase
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

            var tokenValidationParameters = new TokenValidationParameters()
            {
                ValidateAudience = false,
                ValidateIssuer = false,
                ValidateIssuerSigningKey = false,
                ValidateLifetime = false,
                IssuerSigningKey = Default.AsymmetricSigningCredentials.Key
            };

            var callContext = CallContext;
            if (callContext.PropertyBag == null)
                callContext.PropertyBag = new Dictionary<string, object>() { { "testId", TestId } };
            else
                callContext.PropertyBag.Add("testId", TestId);

            return new SignedHttpRequestValidationData(SignedHttpRequestToken is JsonWebToken jwt ? jwt.EncodedToken : "dummy", httpRequestData, tokenValidationParameters, SignedHttpRequestValidationPolicy, callContext);
        }

        public CallContext CallContext { get; set; } = CallContext.Default;

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

        internal SecurityToken SignedHttpRequestToken { get; set; }
    }
}

#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
