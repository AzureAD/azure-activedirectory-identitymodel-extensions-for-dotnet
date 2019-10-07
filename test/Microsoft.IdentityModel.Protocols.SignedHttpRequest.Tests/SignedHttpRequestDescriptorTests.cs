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
using Microsoft.IdentityModel.Protocols.SignedHttpRequest;
using Microsoft.IdentityModel.Tokens;
using Xunit;


namespace Microsoft.IdentityModel.Protocols.SignedHttpRequest.Tests
{
    public class SignedHttpRequestDescriptorTests
    {
        [Fact]
        public void SignedHttpRequestDescriptor()
        {
            var httpRequestData = new HttpRequestData();
            var accessToken = SignedHttpRequestTestUtils.DefaultEncodedAccessToken;
            var signingCredentials = SignedHttpRequestTestUtils.DefaultSigningCredentials;
            var creationPolicy = new SignedHttpRequestCreationPolicy();
            var callContext = CallContext.Default;

            Assert.Throws<ArgumentNullException>("accessToken", () => new SignedHttpRequestDescriptor(null, httpRequestData, null));
            Assert.Throws<ArgumentNullException>("accessToken", () => new SignedHttpRequestDescriptor(null, httpRequestData, null, (SignedHttpRequestCreationPolicy)null));
            Assert.Throws<ArgumentNullException>("accessToken", () => new SignedHttpRequestDescriptor(null, httpRequestData, null, (CallContext)null));
            Assert.Throws<ArgumentNullException>("accessToken", () => new SignedHttpRequestDescriptor(null, httpRequestData, null, null, null));
            Assert.Throws<ArgumentNullException>("accessToken", () => new SignedHttpRequestDescriptor(string.Empty, httpRequestData, null));
            Assert.Throws<ArgumentNullException>("accessToken", () => new SignedHttpRequestDescriptor(string.Empty, httpRequestData, null, (SignedHttpRequestCreationPolicy)null));
            Assert.Throws<ArgumentNullException>("accessToken", () => new SignedHttpRequestDescriptor(string.Empty, httpRequestData, null, (CallContext)null));
            Assert.Throws<ArgumentNullException>("accessToken", () => new SignedHttpRequestDescriptor(string.Empty, httpRequestData, null, null, null));
            Assert.Throws<ArgumentNullException>("httpRequestData", () => new SignedHttpRequestDescriptor(accessToken, null, null, creationPolicy, callContext));
            Assert.Throws<ArgumentNullException>("httpRequestData", () => new SignedHttpRequestDescriptor(accessToken, null, null));
            Assert.Throws<ArgumentNullException>("httpRequestData", () => new SignedHttpRequestDescriptor(accessToken, null, null, (SignedHttpRequestCreationPolicy)null));
            Assert.Throws<ArgumentNullException>("httpRequestData", () => new SignedHttpRequestDescriptor(accessToken, null, null, (CallContext)null));
            Assert.Throws<ArgumentNullException>("signingCredentials", () => new SignedHttpRequestDescriptor(accessToken, httpRequestData, null));
            Assert.Throws<ArgumentNullException>("signingCredentials", () => new SignedHttpRequestDescriptor(accessToken, httpRequestData, null, (SignedHttpRequestCreationPolicy)null));
            Assert.Throws<ArgumentNullException>("signingCredentials", () => new SignedHttpRequestDescriptor(accessToken, httpRequestData, null, (CallContext)null));
            Assert.Throws<ArgumentNullException>("signingCredentials", () => new SignedHttpRequestDescriptor(accessToken, httpRequestData, null, creationPolicy, callContext));
            Assert.Throws<ArgumentNullException>("signedHttpRequestCreationPolicy", () => new SignedHttpRequestDescriptor(accessToken, httpRequestData, signingCredentials, (SignedHttpRequestCreationPolicy)null));
            Assert.Throws<ArgumentNullException>("signedHttpRequestCreationPolicy", () => new SignedHttpRequestDescriptor(accessToken, httpRequestData, signingCredentials, null, callContext));
            Assert.Throws<ArgumentNullException>("callContext", () => new SignedHttpRequestDescriptor(accessToken, httpRequestData, signingCredentials, creationPolicy, null));
            Assert.Throws<ArgumentNullException>("callContext", () => new SignedHttpRequestDescriptor(accessToken, httpRequestData, signingCredentials, (CallContext)null));

            // no exceptions
            var signedHttpRequestDescriptor = new SignedHttpRequestDescriptor(accessToken, httpRequestData, signingCredentials);
            Assert.Equal(httpRequestData, signedHttpRequestDescriptor.HttpRequestData);
            Assert.Equal(accessToken, signedHttpRequestDescriptor.AccessToken);
            Assert.Equal(signingCredentials, signedHttpRequestDescriptor.SigningCredentials);
            Assert.NotNull(signedHttpRequestDescriptor.SignedHttpRequestCreationPolicy);
            Assert.NotNull(signedHttpRequestDescriptor.CallContext);

            signedHttpRequestDescriptor = new SignedHttpRequestDescriptor(accessToken, httpRequestData, signingCredentials, creationPolicy);
            Assert.Equal(httpRequestData, signedHttpRequestDescriptor.HttpRequestData);
            Assert.Equal(accessToken, signedHttpRequestDescriptor.AccessToken);
            Assert.Equal(signingCredentials, signedHttpRequestDescriptor.SigningCredentials);
            Assert.Equal(creationPolicy, signedHttpRequestDescriptor.SignedHttpRequestCreationPolicy);
            Assert.NotNull(signedHttpRequestDescriptor.CallContext);

            signedHttpRequestDescriptor = new SignedHttpRequestDescriptor(accessToken, httpRequestData, signingCredentials, callContext);
            Assert.Equal(httpRequestData, signedHttpRequestDescriptor.HttpRequestData);
            Assert.Equal(accessToken, signedHttpRequestDescriptor.AccessToken);
            Assert.Equal(signingCredentials, signedHttpRequestDescriptor.SigningCredentials);
            Assert.Equal(callContext, signedHttpRequestDescriptor.CallContext);
            Assert.NotNull(signedHttpRequestDescriptor.SignedHttpRequestCreationPolicy);

            signedHttpRequestDescriptor = new SignedHttpRequestDescriptor(accessToken, httpRequestData, signingCredentials, creationPolicy, callContext);
            Assert.Equal(httpRequestData, signedHttpRequestDescriptor.HttpRequestData);
            Assert.Equal(accessToken, signedHttpRequestDescriptor.AccessToken);
            Assert.Equal(signingCredentials, signedHttpRequestDescriptor.SigningCredentials);
            Assert.Equal(creationPolicy, signedHttpRequestDescriptor.SignedHttpRequestCreationPolicy);
            Assert.Equal(callContext, signedHttpRequestDescriptor.CallContext);
        }
    }
}
