//-----------------------------------------------------------------------
// Copyright (c) Microsoft Open Technologies, Inc.
// All Rights Reserved
// Apache License 2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// 
// http://www.apache.org/licenses/LICENSE-2.0
// 
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//-----------------------------------------------------------------------

using Microsoft.IdentityModel.Protocols;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IdentityModel.Test;
using System.Reflection;
using Xunit;

namespace Microsoft.IdentityModel.Test
{
    /// <summary>
    /// 
    /// </summary>
    public class OpenIdConnectMessageTests
    {
        [Fact(DisplayName = "OpenIdConnectMessageTests: Constructors")]
        public void Constructors()
        {
            OpenIdConnectMessage openIdConnectMessage = new OpenIdConnectMessage();
            Assert.Equal(openIdConnectMessage.IssuerAddress, string.Empty);
            openIdConnectMessage = new OpenIdConnectMessage("http://www.got.jwt.com");
            Assert.Equal(openIdConnectMessage.IssuerAddress, "http://www.got.jwt.com");
            ExpectedException expectedException = ExpectedException.ArgumentNullException("IssuerAddress");
            try
            {
                openIdConnectMessage = new OpenIdConnectMessage((string)null);
                expectedException.ProcessNoException();
            }
            catch (Exception exception)
            {
                expectedException.ProcessException(exception);
            }
        }

        [Fact(DisplayName = "OpenIdConnectMessageTests: Defaults")]
        public void Defaults()
        {
            List<string> errors = new List<string>();
            OpenIdConnectMessage message = new OpenIdConnectMessage();
            
            if (message.AcrValues != null)
                errors.Add("message.ArcValues != null");

            if (message.ClientAssertion != null)
                errors.Add("message.ClientAssertion != null");

            if (message.ClientAssertionType != null)
                errors.Add("message.ClientAssertionType != null");

            if (message.ClaimsLocales != null)
                errors.Add("message.ClaimsLocales != null");

            if (message.ClientId != null)
                errors.Add("message.ClientId != null");

            if (message.ClientSecret != null)
                errors.Add("message.ClientSecret != null");

            if (message.Code != null)
                errors.Add("message.Code != null");

            if (message.Display != null)
                errors.Add("message.Display != null");

            if (message.IdTokenHint != null)
                errors.Add("message.IdTokenHint != null");

            if (message.LoginHint != null)
                errors.Add("message.LoginHint != null");

            if (message.MaxAge != null)
                errors.Add("message.MaxAge != null");

            if (message.Prompt != null)
                errors.Add("message.Prompt != null");

            if (message.RedirectUri != null)
                errors.Add("message.RedirectUri != null");

            if (message.State != null)
                errors.Add("message.State != null");

            if (message.UiLocales != null)
                errors.Add("message.UiLocales != null");

            TestUtilities.AssertFailIfErrors("OpenIdConnectMessage_Defaults*** Test Failures:\n", errors);
        }

        [Fact(DisplayName = "OpenIdConnectMessageTests: GetSets")]
        public void GetSets()
        {
            OpenIdConnectMessage message = new OpenIdConnectMessage();
            Type type = typeof(OpenIdConnectMessage);
            PropertyInfo[] properties = type.GetProperties();
            if (properties.Length != 47)
                Assert.True(true, "Number of public fields has changed from 47 to: " + properties.Length + ", adjust tests");

            GetSetContext context =
                new GetSetContext
                {
                    PropertyNamesAndSetGetValue = new List<KeyValuePair<string, List<object>>>
                    {
                        new KeyValuePair<string, List<object>>("IssuerAddress", new List<object>{string.Empty, Guid.NewGuid().ToString(), Guid.NewGuid().ToString()}),
                        new KeyValuePair<string, List<object>>("AuthorizationEndpoint", new List<object>{(string)null, Guid.NewGuid().ToString(), Guid.NewGuid().ToString()}),
                        new KeyValuePair<string, List<object>>("AccessToken", new List<object>{(string)null, Guid.NewGuid().ToString(), Guid.NewGuid().ToString()}),
                        new KeyValuePair<string, List<object>>("AcrValues", new List<object>{(string)null, Guid.NewGuid().ToString(), Guid.NewGuid().ToString()}),
                        new KeyValuePair<string, List<object>>("ClaimsLocales", new List<object>{(string)null, Guid.NewGuid().ToString(), Guid.NewGuid().ToString()}),
                        new KeyValuePair<string, List<object>>("ClientAssertion", new List<object>{(string)null, Guid.NewGuid().ToString(), Guid.NewGuid().ToString()}),
                        new KeyValuePair<string, List<object>>("ClientAssertionType", new List<object>{(string)null, Guid.NewGuid().ToString(), Guid.NewGuid().ToString()}),
                        new KeyValuePair<string, List<object>>("ClientId", new List<object>{(string)null, Guid.NewGuid().ToString(), Guid.NewGuid().ToString()}),
                        new KeyValuePair<string, List<object>>("ClientSecret", new List<object>{(string)null, Guid.NewGuid().ToString(), Guid.NewGuid().ToString()}),
                        new KeyValuePair<string, List<object>>("Code", new List<object>{(string)null, Guid.NewGuid().ToString(), Guid.NewGuid().ToString()}),
                        new KeyValuePair<string, List<object>>("Display", new List<object>{(string)null, Guid.NewGuid().ToString(), Guid.NewGuid().ToString()}),
                        new KeyValuePair<string, List<object>>("DomainHint", new List<object>{(string)null, Guid.NewGuid().ToString(), Guid.NewGuid().ToString()}),
                        new KeyValuePair<string, List<object>>("Error",  new List<object>{(string)null, Guid.NewGuid().ToString(), Guid.NewGuid().ToString()}),
                        new KeyValuePair<string, List<object>>("ErrorDescription",  new List<object>{(string)null, Guid.NewGuid().ToString(), Guid.NewGuid().ToString()}),
                        new KeyValuePair<string, List<object>>("ErrorUri",  new List<object>{(string)null, Guid.NewGuid().ToString(), Guid.NewGuid().ToString()}),
                        new KeyValuePair<string, List<object>>("ExpiresIn",  new List<object>{(string)null, Guid.NewGuid().ToString(), Guid.NewGuid().ToString()}),
                        new KeyValuePair<string, List<object>>("GrantType", new List<object>{(string)null, Guid.NewGuid().ToString(), Guid.NewGuid().ToString()}),
                        new KeyValuePair<string, List<object>>("IdToken", new List<object>{(string)null, Guid.NewGuid().ToString(), Guid.NewGuid().ToString()}),
                        new KeyValuePair<string, List<object>>("IdTokenHint", new List<object>{(string)null, Guid.NewGuid().ToString(), Guid.NewGuid().ToString()}),
                        new KeyValuePair<string, List<object>>("IdentityProvider", new List<object>{(string)null, Guid.NewGuid().ToString(), Guid.NewGuid().ToString()}),
                        new KeyValuePair<string, List<object>>("MaxAge", new List<object>{(string)null, Guid.NewGuid().ToString(), Guid.NewGuid().ToString()}),
                        new KeyValuePair<string, List<object>>("Password", new List<object>{(string)null, Guid.NewGuid().ToString(), Guid.NewGuid().ToString()}),
                        new KeyValuePair<string, List<object>>("PostLogoutRedirectUri", new List<object>{(string)null, Guid.NewGuid().ToString(), Guid.NewGuid().ToString()}),
                        new KeyValuePair<string, List<object>>("Prompt", new List<object>{(string)null, Guid.NewGuid().ToString(), Guid.NewGuid().ToString()}),
                        new KeyValuePair<string, List<object>>("RedirectUri", new List<object>{(string)null, Guid.NewGuid().ToString(), Guid.NewGuid().ToString()}),
                        new KeyValuePair<string, List<object>>("RequestUri", new List<object>{(string)null, Guid.NewGuid().ToString(), Guid.NewGuid().ToString()}),
                        new KeyValuePair<string, List<object>>("ResponseMode", new List<object>{(string)null, Guid.NewGuid().ToString(), Guid.NewGuid().ToString()}),
                        new KeyValuePair<string, List<object>>("ResponseType", new List<object>{(string)null, Guid.NewGuid().ToString(), Guid.NewGuid().ToString()}),
                        new KeyValuePair<string, List<object>>("Resource", new List<object>{(string)null, Guid.NewGuid().ToString(), Guid.NewGuid().ToString()}),
                        new KeyValuePair<string, List<object>>("Scope", new List<object>{null, Guid.NewGuid().ToString(), Guid.NewGuid().ToString()}),
                        new KeyValuePair<string, List<object>>("SessionState", new List<object>{(string)null, Guid.NewGuid().ToString(), Guid.NewGuid().ToString()}),
                        new KeyValuePair<string, List<object>>("State", new List<object>{(string)null, Guid.NewGuid().ToString(), Guid.NewGuid().ToString()}),
                        new KeyValuePair<string, List<object>>("TargetLinkUri", new List<object>{(string)null, Guid.NewGuid().ToString(), Guid.NewGuid().ToString()}),
                        new KeyValuePair<string, List<object>>("Token", new List<object>{(string)null, Guid.NewGuid().ToString(), Guid.NewGuid().ToString()}),
                        new KeyValuePair<string, List<object>>("TokenEndpoint", new List<object>{(string)null, Guid.NewGuid().ToString(), Guid.NewGuid().ToString()}),
                        new KeyValuePair<string, List<object>>("TokenType", new List<object>{(string)null, Guid.NewGuid().ToString(), Guid.NewGuid().ToString()}),
                        new KeyValuePair<string, List<object>>("UiLocales", new List<object>{(string)null, Guid.NewGuid().ToString(), Guid.NewGuid().ToString()}),
                        new KeyValuePair<string, List<object>>("UserId", new List<object>{(string)null, Guid.NewGuid().ToString(), Guid.NewGuid().ToString()}),
                        new KeyValuePair<string, List<object>>("Username", new List<object>{(string)null, Guid.NewGuid().ToString(), Guid.NewGuid().ToString()}),
                    },

                    Object = message,
                };

            TestUtilities.GetSet(context);
            TestUtilities.AssertFailIfErrors("OpenIdConnectMessage_GetSets*** Test Failures:\n", context.Errors);
        }

        [Fact(DisplayName = "OpenIdConnectMessageTests: Publics")]
        public void Publics()
        {
            string issuerAddress = "http://gotJwt.onmicrosoft.com";
            string customParameterName = "Custom Parameter Name";
            string customParameterValue = "Custom Parameter Value";
            string nonce = Guid.NewGuid().ToString();
            string redirectUri = "http://gotJwt.onmicrosoft.com/signedIn";
            string resource = "location data";

            List<string> errors = new List<string>();

            // Empty string
            OpenIdConnectMessage message = new OpenIdConnectMessage();

            string url = message.BuildRedirectUrl();
            string expected = string.Format(CultureInfo.InvariantCulture, @"");
            Report("1", errors, url, expected);

            message.ResponseMode = OpenIdConnectResponseModes.FormPost;
            message.ResponseType = OpenIdConnectResponseTypes.CodeIdToken;
            message.Scope = OpenIdConnectScopes.OpenIdProfile;

            url = message.BuildRedirectUrl();
            expected = string.Format(CultureInfo.InvariantCulture, @"?response_mode=form_post&response_type=code%20id_token&scope=openid%20profile");
            Report("1a", errors, url, expected);

            // Nonce added
            message.Nonce = nonce;
            url = message.BuildRedirectUrl();
            expected = string.Format(CultureInfo.InvariantCulture, @"?response_mode=form_post&response_type=code%20id_token&scope=openid%20profile&nonce={0}", nonce);
            Report("2", errors, url, expected);

            // IssuerAddress only
            message = new OpenIdConnectMessage(issuerAddress);
            message.ResponseMode = OpenIdConnectResponseModes.FormPost;
            message.ResponseType = OpenIdConnectResponseTypes.CodeIdToken;
            message.Scope = OpenIdConnectScopes.OpenIdProfile;
            message.Nonce = nonce;

            url = message.BuildRedirectUrl();
            expected = string.Format(CultureInfo.InvariantCulture, @"{0}?response_mode=form_post&response_type=code%20id_token&scope=openid%20profile&nonce={1}", Uri.EscapeUriString(issuerAddress), nonce);
            Report("3", errors, url, expected);

            // IssuerAdderss and Redirect_uri
            message.RedirectUri = redirectUri;
            url = message.BuildRedirectUrl();
            expected = string.Format(CultureInfo.InvariantCulture, @"{0}?response_mode=form_post&response_type=code%20id_token&scope=openid%20profile&nonce={1}&redirect_uri={2}", Uri.EscapeUriString(issuerAddress), message.Nonce, Uri.EscapeDataString(redirectUri));
            Report("4", errors, url, expected);

            // IssuerAdderss empty and Redirect_uri
            message.IssuerAddress = string.Empty;
            url = message.BuildRedirectUrl();
            expected = string.Format(CultureInfo.InvariantCulture, @"?response_mode=form_post&response_type=code%20id_token&scope=openid%20profile&nonce={0}&redirect_uri={1}", message.Nonce, Uri.EscapeDataString(redirectUri));
            Report("5", errors, url, expected);

            // IssuerAdderss, Redirect_uri, Response
            message = new OpenIdConnectMessage(issuerAddress);
            message.ResponseMode = OpenIdConnectResponseModes.FormPost;
            message.ResponseType = OpenIdConnectResponseTypes.CodeIdToken;
            message.Scope = OpenIdConnectScopes.OpenIdProfile;
            message.Nonce = nonce;
            message.RedirectUri = redirectUri;
            message.Resource = resource;
            url = message.BuildRedirectUrl();
            expected = string.Format(CultureInfo.InvariantCulture, @"{0}?response_mode=form_post&response_type=code%20id_token&scope=openid%20profile&nonce={1}&redirect_uri={2}&resource={3}", issuerAddress, message.Nonce, Uri.EscapeDataString(redirectUri), Uri.EscapeDataString(resource));
            Report("6", errors, url, expected);

            // IssuerAdderss, Redirect_uri, Response, customParam
            message = new OpenIdConnectMessage(issuerAddress);
            message.ResponseMode = OpenIdConnectResponseModes.FormPost;
            message.ResponseType = OpenIdConnectResponseTypes.CodeIdToken;
            message.Scope = OpenIdConnectScopes.OpenIdProfile;
            message.Nonce = nonce;
            message.Parameters.Add(customParameterName, customParameterValue);
            message.RedirectUri = redirectUri;
            message.Resource = resource;
            url = message.BuildRedirectUrl();
            expected = string.Format(CultureInfo.InvariantCulture, @"{0}?response_mode=form_post&response_type=code%20id_token&scope=openid%20profile&nonce={1}&{2}={3}&redirect_uri={4}&resource={5}", issuerAddress, message.Nonce, Uri.EscapeDataString(customParameterName), Uri.EscapeDataString(customParameterValue), Uri.EscapeDataString(redirectUri), Uri.EscapeDataString(resource));
            Report("7", errors, url, expected);

            TestUtilities.AssertFailIfErrors("OpenIdConnectMessage_Publics*** Test Failures:\n", errors);
        }

        [Fact(DisplayName = "OpenIdConnectMessageTests: NULL form parameters")]
        public void NullFormParameters()
        {
            List<KeyValuePair<string, string[]>> formData = new List<KeyValuePair<string, string[]>>();
            formData.Add(new KeyValuePair<string, string[]>("key", new string[] { "data" }));
            formData.Add(new KeyValuePair<string, string[]>("nullData", new string[] { null }));
            formData.Add(new KeyValuePair<string, string[]>("emptyData", new string[] { string.Empty }));
            formData.Add(new KeyValuePair<string, string[]>(null, new string[] { null }));
            formData.Add(new KeyValuePair<string, string[]>(null, null));
            OpenIdConnectMessage msg = new OpenIdConnectMessage(formData);
            Assert.NotNull(msg);
        }

        private void Report(string id, List<string> errors, string url, string expected)
        {
            if (!string.Equals(url, expected, StringComparison.Ordinal))
                errors.Add("id: " + id + Environment.NewLine + "message.BuildRedirectUrl( != expected" + Environment.NewLine + Environment.NewLine + url + Environment.NewLine + Environment.NewLine + expected + Environment.NewLine);
        }

        [Fact]
        public void Extensibility()
        {
            var customOpenIdConnectMessage =
                new CustomOpenIdConnectMessage()
                {
                    AuthenticationRequestUrl = Guid.NewGuid().ToString(),
                    LogoutRequestUrl = Guid.NewGuid().ToString(),
                };

            Assert.True(customOpenIdConnectMessage.AuthenticationRequestUrl == customOpenIdConnectMessage.CreateAuthenticationRequestUrl(), "AuthenticationRequestUrl, CreateAuthenticationRequestUrl: " + customOpenIdConnectMessage.AuthenticationRequestUrl + ", " + customOpenIdConnectMessage.CreateAuthenticationRequestUrl());
            Assert.True(customOpenIdConnectMessage.LogoutRequestUrl == customOpenIdConnectMessage.CreateLogoutRequestUrl(), "LogoutRequestUrl, CreateLogoutRequestUrl(): " + customOpenIdConnectMessage.LogoutRequestUrl + ", " + customOpenIdConnectMessage.CreateLogoutRequestUrl());
        }

        private class CustomOpenIdConnectMessage : OpenIdConnectMessage
        {
            public override string CreateAuthenticationRequestUrl()
            {
                return AuthenticationRequestUrl;
            }

            public override string CreateLogoutRequestUrl()
            {
                return LogoutRequestUrl;
            }

            public string AuthenticationRequestUrl { get; set; }
            public string LogoutRequestUrl { get; set; }
        }
    }
}

