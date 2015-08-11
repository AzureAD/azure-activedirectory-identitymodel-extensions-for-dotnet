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

using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Tests;
using System.Reflection;
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
            RunOpenIdConnectConfigurationTest((IDictionary<string, object>)null, new OpenIdConnectConfiguration(), ExpectedException.ArgumentNullException());
            RunOpenIdConnectConfigurationTest(OpenIdConfigData.OpenIdConnectMetadataString, OpenIdConfigData.OpenIdConnectConfiguration1, ExpectedException.NoExceptionExpected);
        }

        private void RunOpenIdConnectConfigurationTest(object obj, OpenIdConnectConfiguration compareTo, ExpectedException expectedException, bool asString = true)
        {
            bool exceptionHit = false;

            OpenIdConnectConfiguration openIdConnectConfiguration = null;
            try
            {
                if (obj is string)
                {
                    openIdConnectConfiguration = new OpenIdConnectConfiguration(obj as string);
                }
                else if (obj is IDictionary<string, object>)
                {
                    openIdConnectConfiguration = new OpenIdConnectConfiguration(obj as IDictionary<string, object>);
                }
                else
                {
                    if (asString)
                    {
                        openIdConnectConfiguration = new OpenIdConnectConfiguration(obj as string);
                    }
                    else
                    {
                        openIdConnectConfiguration = new OpenIdConnectConfiguration(obj as IDictionary<string, object>);
                    }
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
            if (properties.Length != 39)
                Assert.True(false, "Number of properties has changed from 39 to: " + properties.Length + ", adjust tests");

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
                            new KeyValuePair<string, List<object>>("Issuer",  new List<object>{(string)null, Guid.NewGuid().ToString(), Guid.NewGuid().ToString()}),
                            new KeyValuePair<string, List<object>>("JwksUri",  new List<object>{(string)null, Guid.NewGuid().ToString(), Guid.NewGuid().ToString()}),
                            new KeyValuePair<string, List<object>>("JsonWebKeySet",  new List<object>{null, new JsonWebKeySet()}),
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
