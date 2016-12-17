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
using System.Collections.ObjectModel;
using System.IdentityModel.Tokens;
using System.Web.Script.Serialization;

namespace Microsoft.IdentityModel.Protocols
{
    /// <summary>
    /// Contains OpenIdConnect configuration that can be populated from a json string.
    /// </summary>
    public class OpenIdConnectConfiguration
    {
        private static JavaScriptSerializer _javaScriptSerializer;
        private Collection<string> _idTokenSigningAlgValuesSupported = new Collection<string>();
        private Collection<string> _responseTypesSupported = new Collection<string>();
        private Collection<SecurityKey> _signingKeys = new Collection<SecurityKey>();
        private Collection<SecurityToken> _signingTokens = new Collection<SecurityToken>();
        private Collection<string> _subjectTypesSupported = new Collection<string>();

        static OpenIdConnectConfiguration()
        {
            _javaScriptSerializer = new JavaScriptSerializer();
        }

        /// <summary>
        /// Initializes an new instance of <see cref="OpenIdConnectConfiguration"/>.
        /// </summary>
        public OpenIdConnectConfiguration()
        {
        }

        /// <summary>
        /// Initializes an new instance of <see cref="OpenIdConnectConfiguration"/> from a json string.
        /// </summary>
        /// <param name="json">a json string containing the metadata</param>
        /// <exception cref="ArgumentNullException">if 'json' is null or whitespace.</exception>
        public OpenIdConnectConfiguration(string json)
        {
            if(string.IsNullOrWhiteSpace(json))
            {
                throw new ArgumentNullException("json");
            }

            SetFromDictionary(_javaScriptSerializer.Deserialize<Dictionary<string, object>>(json));
        }

        /// <summary>
        /// Initializes an new instance of <see cref="OpenIdConnectConfiguration"/> from an <see cref="IDictionary{TKey, TValue}"/> string.
        /// </summary>
        /// <param name="dictionary">a <see cref="IDictionary{TKey, TValue}"/>json containing the configuration data.</param>
        /// <exception cref="ArgumentNullException">if 'dictionary' is null.</exception>
        public OpenIdConnectConfiguration(IDictionary<string, object> dictionary)
        {
            if (dictionary == null)
            {
                throw new ArgumentNullException("dictionary");
            }

            SetFromDictionary(dictionary);
        }

        private void SetFromDictionary(IDictionary<string, object> dictionary)
        {
            if (dictionary == null)
            {
                return;
            }

            object obj = null;
            string str = null;
            if (dictionary.TryGetValue(OpenIdProviderMetadataNames.AuthorizationEndpoint, out obj))
            {
                str = obj as string;
                if (str != null)
                {
                    AuthorizationEndpoint = str;
                }
            }

            if (dictionary.TryGetValue(OpenIdProviderMetadataNames.CheckSessionIframe, out obj))
            {
                str = dictionary[OpenIdProviderMetadataNames.CheckSessionIframe] as string;
                if (str != null)
                {
                    CheckSessionIframe = str;
                }
            }

            if (dictionary.TryGetValue(OpenIdProviderMetadataNames.FrontchannelLogoutSessionSupported, out obj))
            {
                str = dictionary[OpenIdProviderMetadataNames.FrontchannelLogoutSessionSupported] as string;
                if (str != null)
                {
                    bool frontchannelLogoutSessionSupported = false;
                    if (Boolean.TryParse(str, out frontchannelLogoutSessionSupported))
                    {
                        FrontchannelLogoutSessionSupported = frontchannelLogoutSessionSupported;
                    }
                }
            }

            if (dictionary.TryGetValue(OpenIdProviderMetadataNames.FrontchannelLogoutSupported, out obj))
            {
                str = dictionary[OpenIdProviderMetadataNames.FrontchannelLogoutSupported] as string;
                if (str != null)
                {
                    bool frontchannelLogoutSupported = false;
                    if (Boolean.TryParse(str, out frontchannelLogoutSupported))
                    {
                        FrontchannelLogoutSupported = frontchannelLogoutSupported;
                    }
                }
            }

            if (dictionary.TryGetValue(OpenIdProviderMetadataNames.EndSessionEndpoint, out obj))
            {
                str = obj as string;
                if (str != null)
                {
                    EndSessionEndpoint = str;
                }
            }

            if (dictionary.TryGetValue(OpenIdProviderMetadataNames.Issuer, out obj))
            {
                str = obj as string;
                if (str != null)
                {
                    Issuer = str;
                }
            }

            if (dictionary.TryGetValue(OpenIdProviderMetadataNames.JwksUri, out obj))
            {
                str = obj as string;
                if (str != null)
                {
                    JwksUri = str;
                }
            }

            if (dictionary.TryGetValue(OpenIdProviderMetadataNames.TokenEndpoint, out obj))
            {
                str = obj as string;
                if (str != null)
                {
                    TokenEndpoint = str;
                }
            }

            if (dictionary.TryGetValue(OpenIdProviderMetadataNames.UserInfoEndpoint, out obj))
            {
                str = obj as string;
                if (str != null)
                {
                    UserInfoEndpoint = str;
                }
            }
        }

        /// <summary>
        /// Gets or sets the authorization endpoint.
        /// </summary>
        public string AuthorizationEndpoint { get; set; }

        /// <summary>
        /// Gets or sets the check_session_iframe.
        /// </summary>
        public string CheckSessionIframe { get; set; }

        /// <summary>
        /// Gets or sets the frontchannel_logout_session_supported.
        /// </summary>
        public bool FrontchannelLogoutSessionSupported { get; set; }

        /// <summary>
        /// Gets or sets the frontchannel_logout_supported.
        /// </summary>
        public bool FrontchannelLogoutSupported { get; set; }

        /// <summary>
        /// Gets or sets the end session endpoint.
        /// </summary>
        public string EndSessionEndpoint { get; set; }

        /// <summary>
        /// Gets the collection of 'id_token_signing_alg_values_supported'.
        /// </summary>
        public ICollection<string> IdTokenSigningAlgValuesSupported
        {
            get
            {
                return _idTokenSigningAlgValuesSupported;
            }
        }

        /// <summary>
        /// Gets or sets the 'issuer'.
        /// </summary>
        public string Issuer { get; set; }

        /// <summary>
        /// Gets or sets the 'jwks_uri'
        /// </summary>
        public string JwksUri{ get; set; }

        /// <summary>
        /// Gets or sets the <see cref="JsonWebKeySet"/>
        /// </summary>
        public JsonWebKeySet JsonWebKeySet {get; set;}

        /// <summary>
        /// Gets the collection of 'response_types_supported'.
        /// </summary>
        public ICollection<string> ResponseTypesSupported
        {
            get
            {
                return _responseTypesSupported;
            }
        }

        /// <summary>
        /// Gets the <see cref="ICollection{SecurityKey}"/> that the IdentityProvider indicates are to be used signing tokens.
        /// </summary>
        public ICollection<SecurityKey> SigningKeys
        {
            get
            {
                return _signingKeys;
            }
        }

        /// <summary>
        /// Gets the <see cref="ICollection{SecurityToken}"/> that the IdentityProvider indicates are to be used signing tokens.
        /// </summary>
        public ICollection<SecurityToken> SigningTokens
        {
            get
            {
                return _signingTokens;
            }
        }

        /// <summary>
        /// Gets the collection of 'subject_types_supported'.
        /// </summary>
        public ICollection<string> SubjectTypesSupported
        {
            get
            {
                return _subjectTypesSupported;
            }
        }

        /// <summary>
        /// Gets or sets the 'token_endpoint'.
        /// </summary>
        public string TokenEndpoint { get; set; }

        /// <summary>
        /// Gets or sets the 'user_info_endpoint'.
        /// </summary>
        public string UserInfoEndpoint { get; set; }

    }
}
