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
using Microsoft.IdentityModel.Protocols.SignedHttpRequest;
using Microsoft.IdentityModel.TestUtils;
using Microsoft.IdentityModel.Tokens;
using Xunit;

#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant

namespace Microsoft.IdentityModel.Protocols.SignedHttpRequest.Tests
{
    public class PopKeyResolvingTests
    {
        [Theory, MemberData(nameof(ResolvePopKeyAsyncTheoryData))]
        public async Task ResolvePopKeyAsync(ResolvePopKeyTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.ResolvePopKeyTheoryData", theoryData);
            try
            {
                var signedHttpRequestValidationContext = theoryData.BuildSignedHttpRequestValidationContext();
                var handler = new SignedHttpRequestHandlerPublic();
                _ = await handler.ResolvePopKeyPublicAsync(theoryData.SignedHttpRequestToken, theoryData.ValidatedAccessToken, signedHttpRequestValidationContext, CancellationToken.None).ConfigureAwait(false);

                if ((bool)signedHttpRequestValidationContext.CallContext.PropertyBag[theoryData.MethodToCall] == false)
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
                        MethodToCall = "trackPopKeyResolver",
                        CallContext = new CallContext()
                        {
                            PropertyBag = new Dictionary<string, object>()
                            {
                                { "trackPopKeyResolver", false }
                            }
                        },
                        SignedHttpRequestValidationPolicy = new SignedHttpRequestValidationPolicy()
                        {
                            PopKeyResolverAsync = async (SecurityToken validatedAccessToken, SignedHttpRequestValidationContext signedHttpRequestValidationContext, CancellationToken cancellationToken) =>
                            {
                                signedHttpRequestValidationContext.CallContext.PropertyBag["trackPopKeyResolver"] = true;
                                return await Task.FromResult<SecurityKey>(null);
                            }
                        },
                        ValidatedAccessToken = accessToken,
                        TestId = "ValidResolverCall",
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
                var signedHttpRequestValidationContext = theoryData.BuildSignedHttpRequestValidationContext();
                var handler = new SignedHttpRequestHandlerPublic();
                _ = handler.ResolvePopKeyFromJwkPublic(theoryData.PopKeyString, signedHttpRequestValidationContext);

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

        [Theory, MemberData(nameof(ResolvePopKeyFromJweTheoryData))]
        public async Task ResolvePopKeyFromJweAsync(ResolvePopKeyTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.ResolvePopKeyFromJwe", theoryData);
            try
            {
                var signedHttpRequestValidationContext = theoryData.BuildSignedHttpRequestValidationContext();
                var handler = new SignedHttpRequestHandlerPublic();
                _ = await handler.ResolvePopKeyFromJwePublicAsync(theoryData.PopKeyString, signedHttpRequestValidationContext, CancellationToken.None).ConfigureAwait(false);

                theoryData.ExpectedException.ProcessNoException(context);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<ResolvePopKeyTheoryData> ResolvePopKeyFromJweTheoryData
        {
            get
            {
                var jwe = SignedHttpRequestTestUtils.EncryptToken(SignedHttpRequestTestUtils.DefaultJwe.ToString(Formatting.None));
                var jweRsa = SignedHttpRequestTestUtils.EncryptToken(SignedHttpRequestTestUtils.DefaultJwk.ToString(Formatting.None));
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
                        ExpectedException = new ExpectedException(typeof(ArgumentException), "IDX14100", null, true),
                        TestId = "InvalidPopKeyNotAJWK",
                    },
                    new ResolvePopKeyTheoryData
                    {
                        PopKeyString = SignedHttpRequestTestUtils.DefaultEncodedAccessToken,
                        ExpectedException = new ExpectedException(typeof(SignedHttpRequestInvalidPopKeyException), "IDX23017"),
                        TestId = "InvalidNoDecryptionKeysSet",
                    },
                    new ResolvePopKeyTheoryData
                    {
                        SignedHttpRequestValidationPolicy = new SignedHttpRequestValidationPolicy()
                        {
                            CnfDecryptionKeysResolverAsync = async (SecurityToken jweCnf, CancellationToken cancellationToken) =>
                            {
                                return await Task.FromResult<IEnumerable<SecurityKey>>(null);
                            }
                        },
                        PopKeyString = SignedHttpRequestTestUtils.DefaultEncodedAccessToken,
                        ExpectedException = new ExpectedException(typeof(SignedHttpRequestInvalidPopKeyException), "IDX23017"),
                        TestId = "InvalidCnfDelegateReturnsNull"
                    },
                    new ResolvePopKeyTheoryData
                    {
                        SignedHttpRequestValidationPolicy = new SignedHttpRequestValidationPolicy()
                        {
                            CnfDecryptionKeysResolverAsync = async (SecurityToken jweCnf, CancellationToken cancellationToken) =>
                            {
                                return await Task.FromResult<IEnumerable<SecurityKey>>(new List<SecurityKey>());
                            }
                        },
                        PopKeyString = SignedHttpRequestTestUtils.DefaultEncodedAccessToken,
                        ExpectedException = new ExpectedException(typeof(SignedHttpRequestInvalidPopKeyException), "IDX23017"),
                        TestId = "InvalidCnfDelegateReturnsEmptyList"
                    },
                    new ResolvePopKeyTheoryData
                    {
                        SignedHttpRequestValidationPolicy = new SignedHttpRequestValidationPolicy()
                        {
                            CnfDecryptionKeys = new List<SecurityKey>() { SignedHttpRequestTestUtils.DefaultEncryptingCredentials.Key }
                        },
                        PopKeyString = SignedHttpRequestTestUtils.DefaultEncodedAccessToken,
                        ExpectedException = new ExpectedException(typeof(SignedHttpRequestInvalidPopKeyException), "IDX23018", null, true),
                        TestId = "InvalidBadToken"
                    },
                    new ResolvePopKeyTheoryData
                    {
                        SignedHttpRequestValidationPolicy = new SignedHttpRequestValidationPolicy()
                        {
                            CnfDecryptionKeys = new List<SecurityKey>() { SignedHttpRequestTestUtils.DefaultEncryptingCredentials.Key }
                        },
                        PopKeyString = jweRsa,
                        ExpectedException = new ExpectedException(typeof(SignedHttpRequestInvalidPopKeyException), "IDX23019"),
                        TestId = "InvalidNotSymmetricKey"
                    },
                    new ResolvePopKeyTheoryData
                    {
                        SignedHttpRequestValidationPolicy = new SignedHttpRequestValidationPolicy()
                        {
                            CnfDecryptionKeysResolverAsync = async (SecurityToken jweCnf, CancellationToken cancellationToken) =>
                            {
                                return await Task.FromResult<IEnumerable<SecurityKey>>(new List<SecurityKey>() { SignedHttpRequestTestUtils.DefaultEncryptingCredentials.Key });
                            }
                        },
                        PopKeyString = jwe,
                        TestId = "ValidCnfDelegateReturnsCorrectKey"
                    },
                    new ResolvePopKeyTheoryData
                    {
                        SignedHttpRequestValidationPolicy = new SignedHttpRequestValidationPolicy()
                        {
                            CnfDecryptionKeys = new List<SecurityKey>() { SignedHttpRequestTestUtils.DefaultEncryptingCredentials.Key }
                        },
                        PopKeyString = jwe,
                        TestId = "ValidTest"
                    },
                };
            }
        }

        [Theory, MemberData(nameof(ResolvePopKeyFromJkuTheoryData))]
        public async Task ResolvePopKeyFromJkuAsync(ResolvePopKeyTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.ResolvePopKeyFromJkuAsync", theoryData);
            try
            {
                var signedHttpRequestValidationContext = theoryData.BuildSignedHttpRequestValidationContext();
                var handler = new SignedHttpRequestHandlerPublic();
                var popKey = await handler.ResolvePopKeyFromJkuPublicAsync(string.Empty, signedHttpRequestValidationContext, CancellationToken.None).ConfigureAwait(false);

                if (popKey == null)
                    context.AddDiff("Resolved Pop key is null.");

                theoryData.ExpectedException.ProcessNoException(context);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<ResolvePopKeyTheoryData> ResolvePopKeyFromJkuTheoryData
        {
            get
            {
                return new TheoryData<ResolvePopKeyTheoryData>
                {
                    new ResolvePopKeyTheoryData
                    {
                        First = true,
                        CallContext = new CallContext()
                        {
                            PropertyBag = new Dictionary<string, object>()
                            {
                                {"mockGetPopKeysFromJkuAsync_return0Keys", null }
                            }
                        },
                        ExpectedException = new ExpectedException(typeof(SignedHttpRequestInvalidPopKeyException), "IDX23020"),
                        TestId = "InvalidZeroKeysReturned",
                    },
                    new ResolvePopKeyTheoryData
                    {
                        CallContext = new CallContext()
                        {
                            PropertyBag = new Dictionary<string, object>()
                            {
                                {"mockGetPopKeysFromJkuAsync_returnNull", null }
                            }
                        },
                        ExpectedException = new ExpectedException(typeof(SignedHttpRequestInvalidPopKeyException), "IDX23020"),
                        TestId = "InvalidNullReturned",
                    },
                    new ResolvePopKeyTheoryData
                    {
                        CallContext = new CallContext()
                        {
                            PropertyBag = new Dictionary<string, object>()
                            {
                                {"mockGetPopKeysFromJkuAsync_return2Keys", null }
                            }
                        },
                        ExpectedException = new ExpectedException(typeof(SignedHttpRequestInvalidPopKeyException), "IDX23020"),
                        TestId = "InvalidTwoKeysReturned",
                    },
                    new ResolvePopKeyTheoryData
                    {
                        CallContext = new CallContext()
                        {
                            PropertyBag = new Dictionary<string, object>()
                            {
                                {"mockGetPopKeysFromJkuAsync_return1Key", null }
                            }
                        },
                        TestId = "ValidOneKeyReturned",
                    },
                };
            }
        }

        [Theory, MemberData(nameof(ResolvePopKeyFromJkuKidTheoryData))]
        public async Task ResolvePopKeyFromJkuKidAsync(ResolvePopKeyTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.ResolvePopKeyFromJkuKidAsync", theoryData);
            try
            {
                var signedHttpRequestValidationContext = theoryData.BuildSignedHttpRequestValidationContext();
                var handler = new SignedHttpRequestHandlerPublic();
                var popKey = await handler.ResolvePopKeyFromJkuPublicAsync(string.Empty, theoryData.Kid, signedHttpRequestValidationContext, CancellationToken.None).ConfigureAwait(false);

                if (popKey == null)
                    context.AddDiff("Resolved Pop key is null.");

                theoryData.ExpectedException.ProcessNoException(context);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<ResolvePopKeyTheoryData> ResolvePopKeyFromJkuKidTheoryData
        {
            get
            {
                return new TheoryData<ResolvePopKeyTheoryData>
                {
                    new ResolvePopKeyTheoryData
                    {
                        First = true,
                        Kid = null,
                        ExpectedException = ExpectedException.ArgumentNullException(),
                        TestId = "InvalidKidNull",
                    },
                    new ResolvePopKeyTheoryData
                    {
                        Kid = string.Empty,
                        ExpectedException = ExpectedException.ArgumentNullException(),
                        TestId = "InvalidEmptyKid",
                    },
                    new ResolvePopKeyTheoryData
                    {
                        Kid = "irelevantForThisTest",
                        CallContext = new CallContext()
                        {
                            PropertyBag = new Dictionary<string, object>()
                            {
                                {"mockGetPopKeysFromJkuAsync_return0Keys", null }
                            }
                        },
                        ExpectedException = new ExpectedException(typeof(SignedHttpRequestInvalidPopKeyException), "IDX23021"),
                        TestId = "InvalidZeroKeysReturned",
                    },
                    new ResolvePopKeyTheoryData
                    {
                        Kid = "irelevantForThisTest",
                        CallContext = new CallContext()
                        {
                            PropertyBag = new Dictionary<string, object>()
                            {
                                {"mockGetPopKeysFromJkuAsync_returnNull", null }
                            }
                        },
                        ExpectedException = new ExpectedException(typeof(SignedHttpRequestInvalidPopKeyException), "IDX23032"),
                        TestId = "InvalidNullReturned",
                    },
                    new ResolvePopKeyTheoryData
                    {
                        Kid = SignedHttpRequestTestUtils.DefaultSigningCredentials.Kid,
                        CallContext = new CallContext()
                        {
                            PropertyBag = new Dictionary<string, object>()
                            {
                                {"mockGetPopKeysFromJkuAsync_returnWrongKey", null }
                            }
                        },
                        ExpectedException = new ExpectedException(typeof(SignedHttpRequestInvalidPopKeyException), "IDX23021"),
                        TestId = "InvalidNoKidMatch",
                    },
                    new ResolvePopKeyTheoryData
                    {
                        Kid = SignedHttpRequestTestUtils.DefaultSigningCredentials.Kid,
                        CallContext = new CallContext()
                        {
                            PropertyBag = new Dictionary<string, object>()
                            {
                                {"mockGetPopKeysFromJkuAsync_return2Keys", null }
                            }
                        },
                        TestId = "ValidOneKidMatch",
                    },
                    new ResolvePopKeyTheoryData
                    {
                        Kid = SignedHttpRequestTestUtils.DefaultSigningCredentials.Kid,
                        CallContext = new CallContext()
                        {
                            PropertyBag = new Dictionary<string, object>()
                            {
                                {"mockGetPopKeysFromJkuAsync_return1Key", null }
                            }
                        },
                        TestId = "ValidKidMatch",
                    },
                };
            }
        }

        [Theory, MemberData(nameof(GetPopKeysFromJkuAsyncTheoryData))]
        public async Task GetPopKeysFromJkuAsync(ResolvePopKeyTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.GetPopKeysFromJkuAsync", theoryData);
            try
            {
                var signedHttpRequestValidationContext = theoryData.BuildSignedHttpRequestValidationContext();
                var handler = new SignedHttpRequestHandlerPublic();
                var popKeys = await handler.GetPopKeysFromJkuPublicAsync(theoryData.JkuSetUrl, signedHttpRequestValidationContext, CancellationToken.None).ConfigureAwait(false);

                if (popKeys.Count != theoryData.ExpectedNumberOfPopKeysReturned)
                    context.AddDiff($"Number of returned pop keys {popKeys.Count} is not the same as the expected: {theoryData.ExpectedNumberOfPopKeysReturned}.");

                theoryData.ExpectedException.ProcessNoException(context);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<ResolvePopKeyTheoryData> GetPopKeysFromJkuAsyncTheoryData
        {
            get
            {
                return new TheoryData<ResolvePopKeyTheoryData>
                {
                    new ResolvePopKeyTheoryData
                    {
                        First = true,
                        JkuSetUrl = null,
                        ExpectedException = ExpectedException.ArgumentNullException(),
                        TestId = "InvalidJkuUrlNull",
                    },
                    new ResolvePopKeyTheoryData
                    {
                        JkuSetUrl = string.Empty,
                        ExpectedException = ExpectedException.ArgumentNullException(),
                        TestId = "InvalidJkuUrlEmptyString",
                    },
                    new ResolvePopKeyTheoryData
                    {
                        JkuSetUrl = "http://www.contoso.com",
                        ExpectedException = new ExpectedException(typeof(SignedHttpRequestInvalidPopKeyException), "IDX23006"),
                        TestId = "InvalidHttpsRequired",
                    },
                    new ResolvePopKeyTheoryData
                    {
                        JkuSetUrl = "https://www.contoso.com",
                        SignedHttpRequestValidationPolicy = new SignedHttpRequestValidationPolicy()
                        {
                            HttpClientForJkuResourceRetrieval = SignedHttpRequestTestUtils.SetupHttpClientThatReturns(string.Empty),
                        },
                        ExpectedException = new ExpectedException(typeof(SignedHttpRequestInvalidPopKeyException), "IDX23022", null, true),
                        TestId = "InvalidNoContentReturned",
                    },
                    new ResolvePopKeyTheoryData
                    {
                        JkuSetUrl = "http://www.contoso.com",
                        SignedHttpRequestValidationPolicy = new SignedHttpRequestValidationPolicy()
                        {
                            RequireHttpsForJkuResourceRetrieval = false,
                            HttpClientForJkuResourceRetrieval = SignedHttpRequestTestUtils.SetupHttpClientThatReturns(string.Empty),
                        },
                        ExpectedException = new ExpectedException(typeof(SignedHttpRequestInvalidPopKeyException), "IDX23022", null, true),
                        TestId = "InvalidHttpNoContentReturned",
                    },
                    new ResolvePopKeyTheoryData
                    {
                        JkuSetUrl = "http://www.contoso.com",
                        SignedHttpRequestValidationPolicy = new SignedHttpRequestValidationPolicy()
                        {
                            RequireHttpsForJkuResourceRetrieval = false,
                        },
                        ExpectedException = new ExpectedException(typeof(SignedHttpRequestInvalidPopKeyException), "IDX23022", typeof(ArgumentException)),
                        TestId = "Valid0KeysReturnedLive",
                    },
                    new ResolvePopKeyTheoryData
                    {
                        JkuSetUrl = "https://www.contoso.com",
                        SignedHttpRequestValidationPolicy = new SignedHttpRequestValidationPolicy()
                        {
                            HttpClientForJkuResourceRetrieval = SignedHttpRequestTestUtils.SetupHttpClientThatReturns("{\"test\": 1}"),
                        },
                        ExpectedNumberOfPopKeysReturned = 0,
                        TestId = "Valid0KeysReturned",
                    },
                    new ResolvePopKeyTheoryData
                    {
                        JkuSetUrl = "https://www.contoso.com",
                        SignedHttpRequestValidationPolicy = new SignedHttpRequestValidationPolicy()
                        {
                            HttpClientForJkuResourceRetrieval = SignedHttpRequestTestUtils.SetupHttpClientThatReturns(DataSets.JsonWebKeySetString2),
                        },
                        ExpectedNumberOfPopKeysReturned = 2,
                        TestId = "Valid2KeysReturned",
                    },
                    new ResolvePopKeyTheoryData
                    {
                        JkuSetUrl = "https://www.contoso.com",
                        SignedHttpRequestValidationPolicy = new SignedHttpRequestValidationPolicy()
                        {
                            HttpClientForJkuResourceRetrieval = SignedHttpRequestTestUtils.SetupHttpClientThatReturns(DataSets.JsonWebKeySetECCString),
                        },
                        ExpectedNumberOfPopKeysReturned = 3,
                        TestId = "Valid3KeysReturned",
                    },
                };
            }
        }

        [Theory, MemberData(nameof(ResolvePopKeyFromKeyIdentifierAsyncTheoryData))]
        public async Task ResolvePopKeyFromKeyIdentifierAsync(ResolvePopKeyTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.ResolvePopKeyFromKeyIdentifierAsync", theoryData);
            try
            {
                var signedHttpRequestValidationContext = theoryData.BuildSignedHttpRequestValidationContext();
                var handler = new SignedHttpRequestHandlerPublic();
                var popKeys = await handler.ResolvePopKeyFromKeyIdentifierPublicAsync(theoryData.Kid, theoryData.ValidatedAccessToken, signedHttpRequestValidationContext, CancellationToken.None).ConfigureAwait(false);
                theoryData.ExpectedException.ProcessNoException(context);
            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<ResolvePopKeyTheoryData> ResolvePopKeyFromKeyIdentifierAsyncTheoryData
        {
            get
            {
                return new TheoryData<ResolvePopKeyTheoryData>
                {
                    new ResolvePopKeyTheoryData
                    {
                        First = true,
                        ExpectedException = new ExpectedException(typeof(SignedHttpRequestInvalidPopKeyException), "IDX23023"),
                        TestId = "InvalidDelegateNotSet",
                    },
                    new ResolvePopKeyTheoryData
                    {
                        SignedHttpRequestValidationPolicy = new SignedHttpRequestValidationPolicy()
                        {
                            PopKeyResolverFromKeyIdAsync = (string kid, SecurityToken validatedAccessToken, SignedHttpRequestValidationContext signedHttpRequestValidationContext, CancellationToken cancellationToken) =>
                            {
                                throw new NotImplementedException();
                            }
                        },
                        ExpectedException = new ExpectedException(typeof(NotImplementedException)),
                        TestId = "InvalidDelegatThrows",
                    },
                    new ResolvePopKeyTheoryData
                    {
                        SignedHttpRequestValidationPolicy = new SignedHttpRequestValidationPolicy()
                        {
                            PopKeyResolverFromKeyIdAsync = async (string kid, SecurityToken validatedAccessToken, SignedHttpRequestValidationContext signedHttpRequestValidationContext, CancellationToken cancellationToken) =>
                            {
                                return await Task.FromResult(SignedHttpRequestTestUtils.DefaultSigningCredentials.Key);
                            }
                        },
                        TestId = "ValidTest",
                    },
                };
            }
        }
    }
    public class ResolvePopKeyTheoryData : TheoryDataBase
    {
        public SignedHttpRequestValidationContext BuildSignedHttpRequestValidationContext()
        {
            var httpRequestData = new HttpRequestData()
            {
                Body = HttpRequestBody,
                Uri = HttpRequestUri,
                Method = HttpRequestMethod,
                Headers = HttpRequestHeaders
            };

            // add testId for debugging purposes
            var callContext = CallContext;
            if (callContext.PropertyBag == null)
                callContext.PropertyBag = new Dictionary<string, object>() { { "testId", TestId } };
            else
                callContext.PropertyBag.Add("testId", TestId);

            // set SignedHttpRequestToken if set and if JsonWebToken, otherwise set "dummy" value
            return new SignedHttpRequestValidationContext(SignedHttpRequestToken is JsonWebToken jwt ? jwt.EncodedToken : "dummy", httpRequestData, SignedHttpRequestTestUtils.DefaultTokenValidationParameters, SignedHttpRequestValidationPolicy, callContext);
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

        public string Kid { get; set; }

        public string JkuSetUrl { get; set; }

        public int ExpectedNumberOfPopKeysReturned { get; set; }
    }
}

#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
