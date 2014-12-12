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
using Xunit;
using System;
using System.Collections.Generic;
using System.IdentityModel.Test;
using System.IdentityModel.Tokens;

namespace Microsoft.IdentityModel.Test
{
    /// <summary>
    /// 
    /// </summary>
    public class OpenIdConnectMetadataTests
    {
        [Fact(DisplayName = "Tests: Constructors")]
        public void OpenIdConnectConfiguration_Constructors()
        {
            RunOpenIdConnectConfigurationTest((string)null, new OpenIdConnectConfiguration(), ExpectedException.ArgumentNullException());
            RunOpenIdConnectConfigurationTest((IDictionary<string, object>)null, new OpenIdConnectConfiguration(), ExpectedException.ArgumentNullException());
            RunOpenIdConnectConfigurationTest(OpenIdConfigData.OpenIdConnectMetadataString, OpenIdConfigData.OpenIdConnectConfiguration1, ExpectedException.NoExceptionExpected);
        }

        private OpenIdConnectConfiguration RunOpenIdConnectConfigurationTest(object obj, OpenIdConnectConfiguration compareTo, ExpectedException expectedException, bool asString = true)
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
                Assert.IsTrue(IdentityComparer.AreEqual(openIdConnectConfiguration, compareTo), "jsonWebKey created from: " + (obj == null ? "NULL" : obj.ToString() + " did not match expected."));
            }

            return openIdConnectConfiguration;
        }

        [Fact(DisplayName = "Tests: Defaults")]
        public void OpenIdConnectConfiguration_Defaults()
        {
            OpenIdConnectConfiguration configuration = new OpenIdConnectConfiguration();
            Assert.IsNull(configuration.AuthorizationEndpoint);
            Assert.IsNull(configuration.EndSessionEndpoint);
            Assert.IsNull(configuration.Issuer);
            Assert.IsNull(configuration.JwksUri);
            Assert.IsNull(configuration.TokenEndpoint);
            Assert.IsNotNull(configuration.SigningKeys);
        }

        [Fact(DisplayName = "Tests: GetSets")]
        public void OpenIdConnectConfiguration_GetSets()
        {
            OpenIdConnectConfiguration configuration = new OpenIdConnectConfiguration();
            TestUtilities.CallAllPublicInstanceAndStaticPropertyGets(configuration, "OpenIdConnectMetadata_GetSets");

            List<string> methods = new List<string> { "AuthorizationEndpoint", "EndSessionEndpoint", "Issuer", "JwksUri", "TokenEndpoint", "UserInfoEndpoint" };
            foreach(string method in methods)
            {
                TestUtilities.GetSet(configuration, method, null, new object[] { Guid.NewGuid().ToString(), null, Guid.NewGuid().ToString() });
            }

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

            Assert.AreEqual(configuration.AuthorizationEndpoint, authorization_Endpoint);
            Assert.AreEqual(configuration.EndSessionEndpoint, end_Session_Endpoint);
            Assert.AreEqual(configuration.Issuer, issuer);
            Assert.AreEqual(configuration.JwksUri, jwks_Uri);
            Assert.AreEqual(configuration.TokenEndpoint, token_Endpoint);
            Assert.IsTrue(IdentityComparer.AreEqual<IEnumerable<SecurityKey>>(configuration.SigningKeys, securityKeys));
        }
    }
}