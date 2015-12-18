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
using System.Reflection;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Tokens.Tests;
using Xunit;

namespace Microsoft.IdentityModel.Protocols.OpenIdConnect.Tests
{
    /// <summary>
    /// 
    /// </summary>
    public class OpenIdConnectConfigurationTests
    {
        [Fact(DisplayName = "OpenIdConnectConfigurationTests: Constructors")]
        public void Constructors()
        {
            RunOpenIdConnectConfigurationTest((string)null, new OpenIdConnectConfiguration(), ExpectedException.ArgumentNullException());
            RunOpenIdConnectConfigurationTest(OpenIdConfigData.OpenIdConnectMetadataString, OpenIdConfigData.OpenIdConnectConfiguration1, ExpectedException.NoExceptionExpected);
        }

        private void RunOpenIdConnectConfigurationTest(object obj, OpenIdConnectConfiguration compareTo, ExpectedException expectedException, bool asString = true)
        {
            bool exceptionHit = false;

            OpenIdConnectConfiguration openIdConnectConfiguration = null;
            try
            {
                if (obj is string || asString)
                {
                    openIdConnectConfiguration = new OpenIdConnectConfiguration(obj as string);
                }
                expectedException.ProcessNoException();
            }
            catch (Exception ex)
            {
                exceptionHit = true;
                expectedException.ProcessException(ex);
            }

            if (!exceptionHit && compareTo != null)
            {
                Assert.True(IdentityComparer.AreEqual(openIdConnectConfiguration, compareTo), "jsonWebKey created from: " + (obj == null ? "NULL" : obj.ToString() + " did not match expected."));
            }
        }

        [Fact(DisplayName = "OpenIdConnectConfigurationTests: Defaults")]
        public void Defaults()
        {
            OpenIdConnectConfiguration configuration = new OpenIdConnectConfiguration();
            Assert.NotNull(configuration.AcrValuesSupported);
            Assert.NotNull(configuration.ClaimsSupported);
            Assert.NotNull(configuration.ClaimsLocalesSupported);
            Assert.NotNull(configuration.ClaimTypesSupported);
            Assert.NotNull(configuration.DisplayValuesSupported);
            Assert.NotNull(configuration.GrantTypesSupported);
            Assert.NotNull(configuration.IdTokenEncryptionAlgValuesSupported);
            Assert.NotNull(configuration.IdTokenEncryptionEncValuesSupported);
            Assert.NotNull(configuration.IdTokenSigningAlgValuesSupported);
            Assert.NotNull(configuration.RequestObjectEncryptionAlgValuesSupported);
            Assert.NotNull(configuration.RequestObjectEncryptionEncValuesSupported);
            Assert.NotNull(configuration.RequestObjectSigningAlgValuesSupported);
            Assert.NotNull(configuration.ResponseModesSupported);
            Assert.NotNull(configuration.ResponseTypesSupported);
            Assert.NotNull(configuration.ScopesSupported);
            Assert.NotNull(configuration.SigningKeys);
            Assert.NotNull(configuration.SubjectTypesSupported);
            Assert.NotNull(configuration.TokenEndpointAuthMethodsSupported);
            Assert.NotNull(configuration.TokenEndpointAuthSigningAlgValuesSupported);
            Assert.NotNull(configuration.UILocalesSupported);
            Assert.NotNull(configuration.UserInfoEndpointEncryptionAlgValuesSupported);
            Assert.NotNull(configuration.UserInfoEndpointEncryptionEncValuesSupported);
            Assert.NotNull(configuration.UserInfoEndpointSigningAlgValuesSupported);
        }

        [Fact(DisplayName = "OpenIdConnectConfigurationTests: GetSets")]
        public void GetSets()
        {
            OpenIdConnectConfiguration configuration = new OpenIdConnectConfiguration();
            Type type = typeof(OpenIdConnectConfiguration);
            PropertyInfo[] properties = type.GetProperties();
            if (properties.Length != 41)
                Assert.True(false, "Number of properties has changed from 41 to: " + properties.Length + ", adjust tests");

            TestUtilities.CallAllPublicInstanceAndStaticPropertyGets(configuration, "OpenIdConnectConfiguration_GetSets");

            GetSetContext context =
                new GetSetContext
                {
                    PropertyNamesAndSetGetValue = new List<KeyValuePair<string, List<object>>>
                        {
                            new KeyValuePair<string, List<object>>("AuthorizationEndpoint", new List<object>{(string)null, Guid.NewGuid().ToString(), Guid.NewGuid().ToString()}),
                            new KeyValuePair<string, List<object>>("CheckSessionIframe", new List<object>{(string)null, Guid.NewGuid().ToString(), Guid.NewGuid().ToString()}),
                            new KeyValuePair<string, List<object>>("ClaimsParameterSupported", new List<object>{false, true, false}),
                            new KeyValuePair<string, List<object>>("EndSessionEndpoint", new List<object>{(string)null, Guid.NewGuid().ToString(), Guid.NewGuid().ToString()}),
                            new KeyValuePair<string, List<object>>("HttpLogoutSupported", new List<object>{false, true, true}),
                            new KeyValuePair<string, List<object>>("Issuer",  new List<object>{(string)null, Guid.NewGuid().ToString(), Guid.NewGuid().ToString()}),
                            new KeyValuePair<string, List<object>>("JwksUri",  new List<object>{(string)null, Guid.NewGuid().ToString(), Guid.NewGuid().ToString()}),
                            new KeyValuePair<string, List<object>>("JsonWebKeySet",  new List<object>{null, new JsonWebKeySet()}),
                            new KeyValuePair<string, List<object>>("LogoutSessionSupported", new List<object>{false, true, true}),
                            new KeyValuePair<string, List<object>>("OpPolicyUri", new List<object>{(string)null, Guid.NewGuid().ToString(), Guid.NewGuid().ToString()}),
                            new KeyValuePair<string, List<object>>("OpTosUri", new List<object>{(string)null, Guid.NewGuid().ToString(), Guid.NewGuid().ToString()}),
                            new KeyValuePair<string, List<object>>("RegistrationEndpoint", new List<object>{(string)null, Guid.NewGuid().ToString(), Guid.NewGuid().ToString()}),
                            new KeyValuePair<string, List<object>>("RequireRequestUriRegistration", new List<object>{false, true, true}),
                            new KeyValuePair<string, List<object>>("RequestParameterSupported", new List<object>{false, true, false}),
                            new KeyValuePair<string, List<object>>("RequestUriParameterSupported", new List<object>{false, true, true}),
                            new KeyValuePair<string, List<object>>("ServiceDocumentation", new List<object>{(string)null, Guid.NewGuid().ToString(), Guid.NewGuid().ToString()}),
                            new KeyValuePair<string, List<object>>("TokenEndpoint", new List<object>{(string)null, Guid.NewGuid().ToString(), Guid.NewGuid().ToString()}),
                            new KeyValuePair<string, List<object>>("UserInfoEndpoint", new List<object>{(string)null, Guid.NewGuid().ToString(), Guid.NewGuid().ToString()}),
                        },

                    Object = configuration,
                };

            TestUtilities.GetSet(context);
            TestUtilities.AssertFailIfErrors("OpenIdConnectConfiguration_GetSets", context.Errors);

            string authorization_Endpoint = Guid.NewGuid().ToString();
            string end_Session_Endpoint = Guid.NewGuid().ToString();
            string issuer = Guid.NewGuid().ToString();
            string jwks_Uri = Guid.NewGuid().ToString();
            string token_Endpoint = Guid.NewGuid().ToString();

            configuration = new OpenIdConnectConfiguration()
            {
                AuthorizationEndpoint = authorization_Endpoint,
                EndSessionEndpoint = end_Session_Endpoint,
                Issuer = issuer,
                JwksUri = jwks_Uri,
                TokenEndpoint = token_Endpoint,
            };

            List<SecurityKey> securityKeys = new List<SecurityKey> { new X509SecurityKey(KeyingMaterial.Cert_1024), new X509SecurityKey(KeyingMaterial.DefaultCert_2048) };
            configuration.SigningKeys.Add(new X509SecurityKey(KeyingMaterial.Cert_1024));
            configuration.SigningKeys.Add(new X509SecurityKey(KeyingMaterial.DefaultCert_2048));

            List<string> errors = new List<string>();

            if (!string.Equals(configuration.AuthorizationEndpoint, authorization_Endpoint))
                errors.Add("");

            if (!string.Equals(configuration.EndSessionEndpoint, end_Session_Endpoint))
                errors.Add("");

            if (!string.Equals(configuration.Issuer, issuer))
                errors.Add("");

            if (!string.Equals(configuration.JwksUri, jwks_Uri))
                errors.Add("");

            if (!string.Equals(configuration.TokenEndpoint, token_Endpoint))
                errors.Add("");

            CompareContext compareContext = new CompareContext();
            if (!IdentityComparer.AreEqual<IEnumerable<SecurityKey>>(configuration.SigningKeys, securityKeys, compareContext))
                errors.AddRange(compareContext.Diffs);

            TestUtilities.AssertFailIfErrors("OpenIdConnectConfiguration_GetSets", errors);
        }

        [Fact(DisplayName = "OpenIdConnectConfigurationTests: Testing OpenIdConnectConfiguration.Write")]
        public void Write()
        {
            string compareToJson = OpenIdConfigData.OpenIdConnectMetadataCompleteString;
            string deserializedJson = OpenIdConnectConfiguration.Write(OpenIdConnectConfiguration.Create(compareToJson));
            Assert.True(deserializedJson.Equals(compareToJson, StringComparison.OrdinalIgnoreCase), "Deserialized json: " + deserializedJson + " does not match with the original json: " + compareToJson);
        }
    }
}
