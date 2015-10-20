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
using System.IdentityModel.Tokens.Tests;
using System.IO;
using System.Net.Http;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Xunit;

namespace Microsoft.IdentityModel.Protocols.OpenIdConnect.Tests
{
    public class OpenIdConnectConfigurationRetrieverTests
    {

        [Fact(DisplayName = "OpenIdConnectConfigurationRetrieverTests: FromNetwork")]
        public async Task FromNetwork()
        {
            OpenIdConnectConfiguration configuration = await GetConfigurationFromHttpAsync(OpenIdConfigData.AADCommonUrl, expectedException: ExpectedException.NoExceptionExpected);
            Assert.NotNull(configuration);
            
            await GetConfigurationFromHttpAsync(string.Empty, expectedException: ExpectedException.ArgumentNullException());
            await GetConfigurationFromHttpAsync(OpenIdConfigData.BadUri, expectedException: ExpectedException.ArgumentException("IDX10108:"));
            await GetConfigurationFromHttpAsync(OpenIdConfigData.HttpsBadUri, expectedException: ExpectedException.IOException(inner: typeof(InvalidOperationException)));
        }

        [Fact(DisplayName = "OpenIdConnectConfigurationRetrieverTests: FromFile")]

        public async Task FromFile()
        {
            CompareContext cc =
                new CompareContext
                {
                    IgnoreType = false,
                };

            OpenIdConnectConfiguration configuration = await GetConfigurationAsync(OpenIdConfigData.OpenIdConnectMetadataFile, expectedException: ExpectedException.NoExceptionExpected);

            Assert.True(IdentityComparer.AreEqual(configuration, OpenIdConfigData.OpenIdConnectConfigurationWithKeys1, cc));

            // jwt_uri points to bad formated JSON
            configuration = await GetConfigurationAsync(OpenIdConfigData.OpenIdConnectMetadataJsonWebKeySetBadUriFile, expectedException: ExpectedException.IOException(inner: typeof(InvalidOperationException)));

            // reading form a file that does not exist
            configuration = await GetConfigurationAsync("FileDoesNotExist.json", expectedException: ExpectedException.IOException(inner: typeof(ArgumentException)));

        }

        [Fact(DisplayName = "OpenIdConnectConfigurationRetrieverTests: FromText")]
        public async Task FromText()
        {
            OpenIdConnectConfiguration configuration;
            List<string> errors = new List<string>();

            configuration = await GetConfigurationFromMixedAsync(OpenIdConfigData.OpenIdConnectMetadataPingString, expectedException: ExpectedException.NoExceptionExpected);

            configuration = await GetConfigurationFromMixedAsync(OpenIdConfigData.OpenIdConnectMetadataPingLabsJWKSString, expectedException: ExpectedException.NoExceptionExpected);
            CompareContext context = new CompareContext();
            if (!IdentityComparer.AreEqual(configuration, OpenIdConfigData.OpenIdConnectConfigurationPingLabsJWKS, context))
            {
                errors.Add("!IdentityComparer.AreEqual(configuration, OpenIdConfigData.OpenIdConnectConfigurationPingLabsJWKS, context)");
                errors.AddRange(context.Diffs);
                context.Diffs.Clear();
            }

            configuration = await GetConfigurationFromMixedAsync(OpenIdConfigData.OpenIdConnectMetadataString, expectedException: ExpectedException.NoExceptionExpected);
            if (!IdentityComparer.AreEqual(configuration, OpenIdConfigData.OpenIdConnectConfigurationWithKeys1, context))
            {
                errors.Add("!IdentityComparer.AreEqual(configuration, OpenIdConfigData.OpenIdConnectConfigurationWithKeys1, context)");
                errors.AddRange(context.Diffs);
                context.Diffs.Clear();
            }

            // jwt_uri is not reachable
            await GetConfigurationFromTextAsync(OpenIdConfigData.OpenIdConnectMetadataBadUriKeysString, string.Empty, expectedException: ExpectedException.IOException());

            // stream is not well formated
            await GetConfigurationFromTextAsync(OpenIdConfigData.OpenIdConnectMetadataBadFormatString, string.Empty, expectedException: new ExpectedException(typeExpected: typeof(Newtonsoft.Json.JsonReaderException)));

            configuration = await GetConfigurationFromMixedAsync(OpenIdConfigData.OpenIdConnectMetadataSingleX509DataString, expectedException: ExpectedException.NoExceptionExpected);
            if(!IdentityComparer.AreEqual(configuration, OpenIdConfigData.OpenIdConnectConfigurationSingleX509Data1, context))
            {
                errors.Add("!IdentityComparer.AreEqual(configuration, OpenIdConfigData.OpenIdConnectConfigurationSingleX509Data1, context)");
                errors.AddRange(context.Diffs);
                context.Diffs.Clear();
            }        

            await GetConfigurationFromMixedAsync(OpenIdConfigData.OpenIdConnectMetadataBadX509DataString, expectedException: ExpectedException.InvalidOperationException(inner: typeof(CryptographicException)));
            await GetConfigurationFromMixedAsync(OpenIdConfigData.OpenIdConnectMetadataBadBase64DataString, expectedException: ExpectedException.InvalidOperationException(inner: typeof(FormatException)));

            TestUtilities.AssertFailIfErrors("OpenIdConnectConfigurationRetrieverTests: FromText", errors);
        }

        [Fact(DisplayName = "OpenIdConnectConfigurationRetrieverTests: Properties")]
        public void Properties()
        {
            // ensure that each property can be set independently
            GetAndCheckConfiguration("authorization_endpoint", "AuthorizationEndpoint");
            GetAndCheckConfiguration("check_session_iframe", "CheckSessionIframe");
            GetAndCheckConfiguration("end_session_endpoint", "EndSessionEndpoint");
            GetAndCheckConfiguration("jwks_uri", "JwksUri", OpenIdConfigData.AADCommonUrl);
            GetAndCheckConfiguration("token_endpoint", "TokenEndpoint");
            GetAndCheckConfiguration("user_info_endpoint", "UserInfoEndpoint");
        }

        private async Task<OpenIdConnectConfiguration> GetConfigurationFromHttpAsync(string uri, ExpectedException expectedException, OpenIdConnectConfiguration expectedConfiguration = null)
        {
            OpenIdConnectConfiguration openIdConnectConfiguration = null;
            try
            {
                openIdConnectConfiguration = await OpenIdConnectConfigurationRetriever.GetAsync(uri, CancellationToken.None);
                expectedException.ProcessNoException();
            }
            catch (Exception exception)
            {
                expectedException.ProcessException(exception);
            }

            if (expectedConfiguration != null)
            {
                Assert.True(IdentityComparer.AreEqual(openIdConnectConfiguration, expectedConfiguration));
            }

            return openIdConnectConfiguration;
        }

        private async Task<OpenIdConnectConfiguration> GetConfigurationAsync(string uri, ExpectedException expectedException, OpenIdConnectConfiguration expectedConfiguration = null)
        {
            OpenIdConnectConfiguration openIdConnectConfiguration = null;
            try
            {
                openIdConnectConfiguration = await OpenIdConnectConfigurationRetriever.GetAsync(uri, new FileDocumentRetriever(), CancellationToken.None);
                expectedException.ProcessNoException();
            }
            catch (Exception exception)
            {
                expectedException.ProcessException(exception);
            }

            if (expectedConfiguration != null)
            {
                Assert.True(IdentityComparer.AreEqual(openIdConnectConfiguration, expectedConfiguration));
            }

            return openIdConnectConfiguration;
        }

        private async Task<OpenIdConnectConfiguration> GetConfigurationFromTextAsync(string primaryDocument, string secondaryDocument, ExpectedException expectedException, OpenIdConnectConfiguration expectedConfiguration = null)
        {
            OpenIdConnectConfiguration openIdConnectConfiguration = null;
            try
            {
                openIdConnectConfiguration = await OpenIdConnectConfigurationRetriever.GetAsync(
                     "primary", new TestDocumentRetriever(primaryDocument, secondaryDocument), CancellationToken.None);
                expectedException.ProcessNoException();
            }
            catch (Exception exception)
            {
                expectedException.ProcessException(exception);
            }

            if (expectedConfiguration != null)
            {
                Assert.True(IdentityComparer.AreEqual(openIdConnectConfiguration, expectedConfiguration));
            }

            return openIdConnectConfiguration;
        }

        private async Task<OpenIdConnectConfiguration> GetConfigurationFromMixedAsync(string primaryDocument, ExpectedException expectedException, OpenIdConnectConfiguration expectedConfiguration = null)
        {
            OpenIdConnectConfiguration openIdConnectConfiguration = null;
            try
            {
                openIdConnectConfiguration = await OpenIdConnectConfigurationRetriever.GetAsync("primary",
                    new TestDocumentRetriever(primaryDocument, new FileDocumentRetriever()), CancellationToken.None);
                expectedException.ProcessNoException();
            }
            catch (Exception exception)
            {
                expectedException.ProcessException(exception);
            }

            if (expectedConfiguration != null)
            {
                Assert.True(IdentityComparer.AreEqual(openIdConnectConfiguration, expectedConfiguration));
            }

            return openIdConnectConfiguration;
        }

        private void GetAndCheckConfiguration(string jsonName, string propertyName, string propertyValue=null)
        {
            string jsonValue = propertyValue;
            if (jsonValue == null)
            {
                jsonValue = Guid.NewGuid().ToString();
            }

            string jsonString = @"{""" + jsonName + @""":""" + jsonValue + @"""}";
            try
            {
                OpenIdConnectConfiguration openIdConnectConfiguration = new OpenIdConnectConfiguration(jsonString);
                OpenIdConnectConfiguration expectedConfiguration = new OpenIdConnectConfiguration();
                TestUtilities.SetProperty(expectedConfiguration, propertyName, jsonValue);
                Assert.True(IdentityComparer.AreEqual(openIdConnectConfiguration, expectedConfiguration));
            }
            catch (Exception exception)
            {
                ExpectedException.NoExceptionExpected.ProcessException(exception);
            }

            return;
        }

        private class TestDocumentRetriever : IDocumentRetriever
        {
            private string _primaryDocument;
            private string _secondaryDocument;
            private IDocumentRetriever _fallback;

            public TestDocumentRetriever(string primaryDocument, string secondaryDocument)
            {
                _primaryDocument = primaryDocument;
                _secondaryDocument = secondaryDocument;
            }

            public TestDocumentRetriever(string primaryDocument, IDocumentRetriever fallback)
            {
                _primaryDocument = primaryDocument;
                _fallback = fallback;
            }
            
            public Task<string> GetDocumentAsync(string address, CancellationToken cancel)
            {
                if (string.Equals("primary", address))
                {
                    return Task.FromResult(_primaryDocument);
                }
                if (string.Equals("secondary", address) && !string.IsNullOrWhiteSpace(_secondaryDocument))
                {
                    return Task.FromResult(_secondaryDocument);
                }
                if (_fallback != null)
                {
                    return _fallback.GetDocumentAsync(address, cancel);
                }
                throw new IOException("Document not found: " + address);
            }
        }
    }
}
