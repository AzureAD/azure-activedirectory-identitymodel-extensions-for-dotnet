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
using System.Globalization;
using System.Reflection;
using Microsoft.IdentityModel.Tokens.Tests;
using Newtonsoft.Json.Linq;
using Xunit;

namespace Microsoft.IdentityModel.Protocols.OpenIdConnect.Tests
{
    /// <summary>
    /// 
    /// </summary>
    public class OpenIdConnectMessageTests
    {
        [Fact]
        public void Constructors()
        {
            OpenIdConnectMessage openIdConnectMessage = new OpenIdConnectMessage();
            Assert.Equal(openIdConnectMessage.IssuerAddress, string.Empty);
            openIdConnectMessage = new OpenIdConnectMessage() { IssuerAddress = "http://www.got.jwt.com" };
            Assert.Equal(openIdConnectMessage.IssuerAddress, "http://www.got.jwt.com");
            ExpectedException expectedException = ExpectedException.NoExceptionExpected;
            string json = @"{""response_mode"":""responseMode"", ""response_type"":""responseType"", ""refresh_token"":""refreshToken""}";
            string badJson = @"{""response_mode"":""responseMode"";""respone_mode"":""badResponeMode""}";

            // null stirng json
            expectedException = ExpectedException.ArgumentNullException();
            TestJsonStringConstructor((string)null, expectedException);

            // bad string json
            expectedException = ExpectedException.ArgumentException("IDX10106");
            TestJsonStringConstructor(badJson, expectedException);

            // no exception, well-formed json
            expectedException = ExpectedException.NoExceptionExpected;
            openIdConnectMessage = TestJsonStringConstructor(json, expectedException);
            Assert.True(openIdConnectMessage.RefreshToken.Equals("refreshToken"), "openIdConnectMessage.RefreshToken does not match expected value: refreshToken");
            Assert.True(openIdConnectMessage.ResponseMode.Equals("responseMode"), "openIdConnectMessage.ResponseMode does not match expected value: refreshToken");
            Assert.True(openIdConnectMessage.ResponseType.Equals("responseType"), "openIdConnectMessage.ResponseType does not match expected value: refreshToken");
            Assert.True(openIdConnectMessage.ClientId == null, "openIdConnectMessage.ClientId is not null");

            // no exception, using JObject ctor
            expectedException = ExpectedException.NoExceptionExpected;
            try
            {
                openIdConnectMessage = new OpenIdConnectMessage(JObject.Parse(json));
                expectedException.ProcessNoException();
            }
            catch (Exception exception)
            {
                expectedException.ProcessException(exception);
            }

            Assert.True(openIdConnectMessage.RefreshToken.Equals("refreshToken"), "openIdConnectMessage.RefreshToken does not match expected value: refreshToken");
            Assert.True(openIdConnectMessage.ResponseMode.Equals("responseMode"), "openIdConnectMessage.ResponseMode does not match expected value: refreshToken");
            Assert.True(openIdConnectMessage.ResponseType.Equals("responseType"), "openIdConnectMessage.ResponseType does not match expected value: refreshToken");
            Assert.True(openIdConnectMessage.ClientId == null, "openIdConnectMessage.ClientId is not null");

            // test with an empty JObject
            openIdConnectMessage = new OpenIdConnectMessage(new JObject());
        }

        private OpenIdConnectMessage TestJsonStringConstructor(string json, ExpectedException expectedException)
        {
            OpenIdConnectMessage openIdConnectMessage = null;

            try
            {
                openIdConnectMessage = new OpenIdConnectMessage(json);
                expectedException.ProcessNoException();
            }
            catch (Exception exception)
            {
                expectedException.ProcessException(exception);
            }

            return openIdConnectMessage;
        }

        [Fact]
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

        [Fact]
        public void GetSets()
        {
            OpenIdConnectMessage message = new OpenIdConnectMessage();
            Type type = typeof(OpenIdConnectMessage);
            PropertyInfo[] properties = type.GetProperties();
            if (properties.Length != 48)
                Assert.True(true, "Number of public fields has changed from 48 to: " + properties.Length + ", adjust tests");

            GetSetContext context =
                new GetSetContext
                {
                    PropertyNamesAndSetGetValue = new List<KeyValuePair<string, List<object>>>
                    {
                        new KeyValuePair<string, List<object>>("AuthorizationEndpoint", new List<object>{(string)null, Guid.NewGuid().ToString(), Guid.NewGuid().ToString()}),
                        new KeyValuePair<string, List<object>>("AccessToken", new List<object>{(string)null, Guid.NewGuid().ToString(), Guid.NewGuid().ToString()}),
                        new KeyValuePair<string, List<object>>("AcrValues", new List<object>{(string)null, Guid.NewGuid().ToString(), Guid.NewGuid().ToString()}),
                        new KeyValuePair<string, List<object>>("ClaimsLocales", new List<object>{(string)null, Guid.NewGuid().ToString(), Guid.NewGuid().ToString()}),
                        new KeyValuePair<string, List<object>>("ClientAssertion", new List<object>{(string)null, Guid.NewGuid().ToString(), Guid.NewGuid().ToString()}),
                        new KeyValuePair<string, List<object>>("ClientAssertionType", new List<object>{(string)null, Guid.NewGuid().ToString(), Guid.NewGuid().ToString()}),
                        new KeyValuePair<string, List<object>>("ClientId", new List<object>{(string)null, Guid.NewGuid().ToString(), Guid.NewGuid().ToString()}),
                        new KeyValuePair<string, List<object>>("ClientSecret", new List<object>{(string)null, Guid.NewGuid().ToString(), Guid.NewGuid().ToString()}),
                        new KeyValuePair<string, List<object>>("Code", new List<object>{(string)null, Guid.NewGuid().ToString(), Guid.NewGuid().ToString()}),
                        new KeyValuePair<string, List<object>>("EnableTelemetryParameters", new List<object>{true, false, false}),
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
                        new KeyValuePair<string, List<object>>("IssuerAddress", new List<object>{string.Empty, Guid.NewGuid().ToString(), Guid.NewGuid().ToString()}),
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
                        new KeyValuePair<string, List<object>>("Sid", new List<object>{(string)null, Guid.NewGuid().ToString(), Guid.NewGuid().ToString()}),
                        new KeyValuePair<string, List<object>>("State", new List<object>{(string)null, Guid.NewGuid().ToString(), Guid.NewGuid().ToString()}),
                        new KeyValuePair<string, List<object>>("TargetLinkUri", new List<object>{(string)null, Guid.NewGuid().ToString(), Guid.NewGuid().ToString()}),
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

#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant
        [Theory, MemberData("CreateAuthenticationRequestUrlTheoryData")]
#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
        public void OidcCreateAuthenticationRequestUrl(string testId, OpenIdConnectMessage message, string expectedMessage)
        {
            Assert.Equal(message.CreateAuthenticationRequestUrl(), expectedMessage);
        }

        public static TheoryData<string, OpenIdConnectMessage, string> CreateAuthenticationRequestUrlTheoryData()
        {
            string customParameterName = "Custom Parameter Name";
            string customParameterValue = "Custom Parameter Value";
            string nonce = Guid.NewGuid().ToString();
            string redirectUri = "http://gotJwt.onmicrosoft.com/signedIn";
            string resource = "location data";

            var theoryData = new TheoryData<string, OpenIdConnectMessage, string>();
            OpenIdConnectMessage.EnableTelemetryParametersByDefault = false;
            var message = new OpenIdConnectMessage();

            theoryData.Add("EmptyMessage", message, "");

            theoryData.Add(
                "Code",
                message = new OpenIdConnectMessage()
                {
                    ResponseMode = OpenIdConnectResponseMode.FormPost,
                    ResponseType = OpenIdConnectResponseType.Code,
                    Scope = OpenIdConnectScope.OpenIdProfile
                },
                string.Format(CultureInfo.InvariantCulture, @"?response_mode=form_post&response_type={0}&scope=openid%20profile", Uri.EscapeUriString(OpenIdConnectResponseType.Code))
            );

            theoryData.Add(
                "CodeIdToken",
                message = new OpenIdConnectMessage()
                {
                    ResponseMode = OpenIdConnectResponseMode.FormPost,
                    ResponseType = OpenIdConnectResponseType.CodeIdToken,
                    Scope = OpenIdConnectScope.OpenIdProfile
                },
                string.Format(CultureInfo.InvariantCulture, @"?response_mode=form_post&response_type={0}&scope=openid%20profile", Uri.EscapeUriString(OpenIdConnectResponseType.CodeIdToken))
            );

            theoryData.Add(
                "CodeIdTokenToken",
                message = new OpenIdConnectMessage()
                {
                    ResponseMode = OpenIdConnectResponseMode.FormPost,
                    ResponseType = OpenIdConnectResponseType.CodeIdTokenToken,
                    Scope = OpenIdConnectScope.OpenIdProfile
                },
                string.Format(CultureInfo.InvariantCulture, @"?response_mode=form_post&response_type={0}&scope=openid%20profile", Uri.EscapeUriString(OpenIdConnectResponseType.CodeIdTokenToken))
            );

            theoryData.Add(
                "CodeToken",
                message = new OpenIdConnectMessage()
                {
                    ResponseMode = OpenIdConnectResponseMode.FormPost,
                    ResponseType = OpenIdConnectResponseType.CodeToken,
                    Scope = OpenIdConnectScope.OpenIdProfile
                },
                string.Format(CultureInfo.InvariantCulture, @"?response_mode=form_post&response_type={0}&scope=openid%20profile", Uri.EscapeUriString(OpenIdConnectResponseType.CodeToken))
            );

            theoryData.Add(
                "IdToken",
                message = new OpenIdConnectMessage()
                {
                    ResponseMode = OpenIdConnectResponseMode.FormPost,
                    ResponseType = OpenIdConnectResponseType.IdToken,
                    Scope = OpenIdConnectScope.OpenIdProfile
                },
                string.Format(CultureInfo.InvariantCulture, @"?response_mode=form_post&response_type={0}&scope=openid%20profile", Uri.EscapeUriString(OpenIdConnectResponseType.IdToken))
            );

            theoryData.Add(
                "IdTokenToken",
                message = new OpenIdConnectMessage()
                {
                    ResponseMode = OpenIdConnectResponseMode.FormPost,
                    ResponseType = OpenIdConnectResponseType.IdTokenToken,
                    Scope = OpenIdConnectScope.OpenIdProfile
                },
                string.Format(CultureInfo.InvariantCulture, @"?response_mode=form_post&response_type={0}&scope=openid%20profile", Uri.EscapeUriString(OpenIdConnectResponseType.IdTokenToken))
            );

            theoryData.Add(
                "None",
                message = new OpenIdConnectMessage()
                {
                    ResponseMode = OpenIdConnectResponseMode.FormPost,
                    ResponseType = OpenIdConnectResponseType.None,
                    Scope = OpenIdConnectScope.OpenIdProfile
                },
                string.Format(CultureInfo.InvariantCulture, @"?response_mode=form_post&response_type={0}&scope=openid%20profile", Uri.EscapeUriString(OpenIdConnectResponseType.None))
            );

            theoryData.Add(
                "Token",
                message = new OpenIdConnectMessage()
                {
                    ResponseMode = OpenIdConnectResponseMode.FormPost,
                    ResponseType = OpenIdConnectResponseType.Token,
                    Scope = OpenIdConnectScope.OpenIdProfile
                },
                string.Format(CultureInfo.InvariantCulture, @"?response_mode=form_post&response_type={0}&scope=openid%20profile", Uri.EscapeUriString(OpenIdConnectResponseType.Token))
            );

            theoryData.Add(
                "Nonce",
                message = new OpenIdConnectMessage()
                {
                    ResponseMode = OpenIdConnectResponseMode.FormPost,
                    ResponseType = OpenIdConnectResponseType.CodeIdToken,
                    Scope = OpenIdConnectScope.OpenIdProfile,
                    Nonce = nonce
                },
                string.Format(CultureInfo.InvariantCulture, @"?response_mode=form_post&response_type=code%20id_token&scope=openid%20profile&nonce={0}", nonce)
            );

            theoryData.Add(
                "IssuerAddress",
                message = new OpenIdConnectMessage()
                {
                    IssuerAddress = Default.Issuer,
                    ResponseMode = OpenIdConnectResponseMode.FormPost,
                    ResponseType = OpenIdConnectResponseType.CodeIdToken,
                    Scope = OpenIdConnectScope.OpenIdProfile,
                    Nonce = nonce
                },
                string.Format(CultureInfo.InvariantCulture, @"{0}?response_mode=form_post&response_type=code%20id_token&scope=openid%20profile&nonce={1}", Uri.EscapeUriString(Default.Issuer), nonce)
            );

            theoryData.Add(
                "IssuerAddress",
                message = new OpenIdConnectMessage()
                {
                    IssuerAddress = Default.Issuer,
                    ResponseMode = OpenIdConnectResponseMode.FormPost,
                    ResponseType = OpenIdConnectResponseType.CodeIdToken,
                    Scope = OpenIdConnectScope.OpenIdProfile,
                    Nonce = nonce,
                    RedirectUri = redirectUri
                },
                string.Format(CultureInfo.InvariantCulture, @"{0}?response_mode=form_post&response_type=code%20id_token&scope=openid%20profile&nonce={1}&redirect_uri={2}", Uri.EscapeUriString(Default.Issuer), nonce, Uri.EscapeDataString(redirectUri))
            );

            theoryData.Add(
                "IssuerAddressEmpty",
                message = new OpenIdConnectMessage()
                {
                    IssuerAddress = string.Empty,
                    ResponseMode = OpenIdConnectResponseMode.FormPost,
                    ResponseType = OpenIdConnectResponseType.CodeIdToken,
                    Scope = OpenIdConnectScope.OpenIdProfile,
                    Nonce = nonce,
                    RedirectUri = redirectUri
                },
                string.Format(CultureInfo.InvariantCulture, @"?response_mode=form_post&response_type=code%20id_token&scope=openid%20profile&nonce={0}&redirect_uri={1}", nonce, Uri.EscapeDataString(redirectUri))
            );

            theoryData.Add(
                "Resource",
                message = new OpenIdConnectMessage()
                {
                    IssuerAddress = Default.Issuer,
                    ResponseMode = OpenIdConnectResponseMode.FormPost,
                    ResponseType = OpenIdConnectResponseType.CodeIdToken,
                    Scope = OpenIdConnectScope.OpenIdProfile,
                    Nonce = nonce,
                    RedirectUri = redirectUri,
                    Resource = resource
                },
                string.Format(CultureInfo.InvariantCulture, @"{0}?response_mode=form_post&response_type=code%20id_token&scope=openid%20profile&nonce={1}&redirect_uri={2}&resource={3}", Default.Issuer, nonce, Uri.EscapeDataString(redirectUri), Uri.EscapeDataString(resource))
            );

            message = new OpenIdConnectMessage()
            {
                IssuerAddress = Default.Issuer,
                ResponseMode = OpenIdConnectResponseMode.FormPost,
                ResponseType = OpenIdConnectResponseType.CodeIdToken,
                Scope = OpenIdConnectScope.OpenIdProfile,
                Nonce = nonce,
            };
            message.Parameters.Add(customParameterName, customParameterValue);
            message.RedirectUri = redirectUri;
            message.Resource = resource;

            theoryData.Add(
                "CustomParam",
                message,
                string.Format(CultureInfo.InvariantCulture, @"{0}?response_mode=form_post&response_type=code%20id_token&scope=openid%20profile&nonce={1}&{2}={3}&redirect_uri={4}&resource={5}", Default.Issuer, nonce, Uri.EscapeDataString(customParameterName), Uri.EscapeDataString(customParameterValue), Uri.EscapeDataString(redirectUri), Uri.EscapeDataString(resource))
            );

            message = new OpenIdConnectMessage();
            theoryData.Add(
                "Resource",
                message = new OpenIdConnectMessage()
                {
                    IssuerAddress = Default.Issuer,
                    ResponseMode = OpenIdConnectResponseMode.FormPost,
                    ResponseType = OpenIdConnectResponseType.CodeIdToken,
                    Scope = OpenIdConnectScope.OpenIdProfile,
                    Nonce = nonce,
                    RedirectUri = redirectUri,
                    Resource = resource
                },
                string.Format(CultureInfo.InvariantCulture, @"{0}?response_mode=form_post&response_type=code%20id_token&scope=openid%20profile&nonce={1}&redirect_uri={2}&resource={3}", Default.Issuer, nonce, Uri.EscapeDataString(redirectUri), Uri.EscapeDataString(resource))
            );

            OpenIdConnectMessage.EnableTelemetryParametersByDefault = true;
            theoryData.Add(
                "Telemetry",
                new OpenIdConnectMessage(),
                string.Format(CultureInfo.InvariantCulture, @"?x-client-SKU=ID_NET&x-client-ver={0}", typeof(OpenIdConnectMessage).GetTypeInfo().Assembly.GetName().Version.ToString())
            );

            // Telemetry turned off
            OpenIdConnectMessage.EnableTelemetryParametersByDefault = false;
            message = new OpenIdConnectMessage();
            message.EnableTelemetryParameters = true;
            theoryData.Add(
                "TelemetryStaticFalseInstanceTrue",
                message,
                string.Format(CultureInfo.InvariantCulture, @"?x-client-SKU=ID_NET&x-client-ver={0}", typeof(OpenIdConnectMessage).GetTypeInfo().Assembly.GetName().Version.ToString())
            );

            // Telemetry turned off using static switch
            OpenIdConnectMessage.EnableTelemetryParametersByDefault = false;
            message = new OpenIdConnectMessage();
            theoryData.Add(
                "TelemetryStaticFalse",
                message,
                ""
            );

            // Telemetry turned off using static switch, but turned on on the instance
            OpenIdConnectMessage.EnableTelemetryParametersByDefault = true;
            message = new OpenIdConnectMessage();
            message.EnableTelemetryParameters = false;
            theoryData.Add(
                "TelemetryStaticTrueInstanceFalse",
                message,
                ""
            );

            OpenIdConnectMessage.EnableTelemetryParametersByDefault = true;

            return theoryData;
        }

#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant
        [Theory, MemberData("CreateLogoutRequestUrlTheoryData")]
#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
        public void OidcCreateLogoutRequestUrl(string testId, OpenIdConnectMessage message, string expectedMessage)
        {
            Assert.Equal(message.CreateLogoutRequestUrl(), expectedMessage);
        }

        public static TheoryData<string, OpenIdConnectMessage, string> CreateLogoutRequestUrlTheoryData()
        {
            var theoryData = new TheoryData<string, OpenIdConnectMessage, string>();

            OpenIdConnectMessage.EnableTelemetryParametersByDefault = true;
            var message = new OpenIdConnectMessage();
            theoryData.Add(
                "Telemetry",
                message,
                string.Format(CultureInfo.InvariantCulture, @"?x-client-SKU=ID_NET&x-client-ver={0}", typeof(OpenIdConnectMessage).GetTypeInfo().Assembly.GetName().Version.ToString())
            );

            // Telemetry turned off using static switch
            OpenIdConnectMessage.EnableTelemetryParametersByDefault = false;
            message = new OpenIdConnectMessage();
            theoryData.Add(
                "TelemetryStaticFalse",
                message,
                ""
            );

            // Telemetry turned off using static switch
            OpenIdConnectMessage.EnableTelemetryParametersByDefault = false;
            message = new OpenIdConnectMessage();
            message.EnableTelemetryParameters = true;
            theoryData.Add(
                "TelemetryStaticFalseInstanceTrue",
                message,
                string.Format(CultureInfo.InvariantCulture, @"?x-client-SKU=ID_NET&x-client-ver={0}", typeof(OpenIdConnectMessage).GetTypeInfo().Assembly.GetName().Version.ToString())
            );

            return theoryData;
        }


        [Fact]
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

        [Fact]
        public void OpenIdConnectMessage_IssuerAddressHasQuery()
        {
            List<string> errors = new List<string>();
            var address = "http://gotJwt.onmicrosoft.com/?param=value";
            var clientId = Guid.NewGuid().ToString();
            var message = new OpenIdConnectMessage() { IssuerAddress = address };

            var url = message.BuildRedirectUrl();
            Report("1", errors, url, address);

            message.ClientId = clientId;
            url = message.BuildRedirectUrl();
            var expected = string.Format(CultureInfo.InvariantCulture, @"{0}&client_id={1}", address, clientId);

            Report("2", errors, url, expected);
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

