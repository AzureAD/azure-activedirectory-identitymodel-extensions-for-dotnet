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
using System.IdentityModel.Test;
using System.IdentityModel.Tokens;
using Xunit;

namespace Microsoft.IdentityModel.Test
{
    /// <summary>
    /// 
    /// </summary>
    public class OpenIdConnectMetadataTests
    {
        [Fact(DisplayName = "OpenIdConnectMetadataTests: Constructors")]
        public void Constructors()
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
                Assert.True(IdentityComparer.AreEqual(openIdConnectConfiguration, compareTo), "jsonWebKey created from: " + (obj == null ? "NULL" : obj.ToString() + " did not match expected."));
            }

            return openIdConnectConfiguration;
        }

        [Fact(DisplayName = "OpenIdConnectMetadataTests: Defaults")]
        public void Defaults()
        {
            OpenIdConnectConfiguration configuration = new OpenIdConnectConfiguration();
            Assert.Null(configuration.AuthorizationEndpoint);
            Assert.Null(configuration.EndSessionEndpoint);
            Assert.Null(configuration.Issuer);
            Assert.Null(configuration.JwksUri);
            Assert.Null(configuration.TokenEndpoint);
            Assert.NotNull(configuration.SigningKeys);
        }

        [Fact(DisplayName = "OpenIdConnectMetadataTests: GetSets")]
        public void GetSets()
        {
            OpenIdConnectConfiguration configuration = new OpenIdConnectConfiguration();
            TestUtilities.CallAllPublicInstanceAndStaticPropertyGets(configuration, "OpenIdConnectMetadata_GetSets");

            List<string> methods = new List<string> { "AuthorizationEndpoint", "EndSessionEndpoint", "Issuer", "JwksUri", "TokenEndpoint", "UserInfoEndpoint" };
            List<string> errors = new List<string>();
            foreach(string method in methods)
            {
                TestUtilities.GetSet(configuration, method, null, new object[] { Guid.NewGuid().ToString(), null, Guid.NewGuid().ToString() }, errors);
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

            CompareContext context = new CompareContext();
            if (!IdentityComparer.AreEqual<IEnumerable<SecurityKey>>(configuration.SigningKeys, securityKeys, context))
                errors.AddRange(context.Diffs);

            TestUtilities.AssertFailIfErrors("OpenIdConnectConfiguration_GetSets", errors);
        }
    }
}