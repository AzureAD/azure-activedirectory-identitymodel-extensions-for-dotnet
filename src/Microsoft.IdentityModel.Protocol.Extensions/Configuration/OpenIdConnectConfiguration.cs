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
using System.Diagnostics.Tracing;
using System.Globalization;
using System.IdentityModel.Tokens;
using Microsoft.IdentityModel.Logging;
using Newtonsoft.Json;

namespace Microsoft.IdentityModel.Protocols
{
    /// <summary>
    /// Contains OpenIdConnect configuration that can be populated from a json string.
    /// </summary>
    [JsonObject]
    public class OpenIdConnectConfiguration
    {
        private Collection<string> _idTokenSigningAlgValuesSupported = new Collection<string>();
        private Collection<string> _responseTypesSupported = new Collection<string>();
        private Collection<SecurityKey> _signingKeys = new Collection<SecurityKey>();
        private Collection<SecurityToken> _signingTokens = new Collection<SecurityToken>();
        private Collection<string> _subjectTypesSupported = new Collection<string>();

        static OpenIdConnectConfiguration()
        {
        }

        static public OpenIdConnectConfiguration Create(string json)
        {
            if (string.IsNullOrWhiteSpace(json))
            {
                LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, ErrorMessages.IDX10000, "OpenIdConnectConfiguration.Create: json"), typeof(ArgumentNullException), EventLevel.Verbose);
            }

            IdentityModelEventSource.Logger.WriteInformation("Deserializing json into OpenIdConnectConfiguration object");
            return JsonConvert.DeserializeObject<OpenIdConnectConfiguration>(json);
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
                LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, ErrorMessages.IDX10000, GetType() + ": json"), typeof(ArgumentNullException), EventLevel.Verbose);
            }

            OpenIdConnectConfiguration config = Create(json);
            Copy(config);
        }

        private void Copy(OpenIdConnectConfiguration config)
        {
            IdentityModelEventSource.Logger.WriteVerbose("Copying openIdConnect configuration object.");
            AuthorizationEndpoint = config.AuthorizationEndpoint;
            CheckSessionIframe = config.CheckSessionIframe;
            EndSessionEndpoint = config.EndSessionEndpoint;
            _idTokenSigningAlgValuesSupported = config._idTokenSigningAlgValuesSupported;
            Issuer = config.Issuer;
            JwksUri = config.JwksUri;
            JsonWebKeySet = config.JsonWebKeySet;
            _responseTypesSupported = config._responseTypesSupported;
            _signingKeys = config._signingKeys;
            TokenEndpoint = config.TokenEndpoint;
            UserInfoEndpoint = config.UserInfoEndpoint;
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
                LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, ErrorMessages.IDX10000, GetType() + ": dictionary"), typeof(ArgumentNullException), EventLevel.Verbose);
            }

            IdentityModelEventSource.Logger.WriteVerbose("Initializing an instance of OpenIdConnectConfiguration from a dictionary.");

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
        }

        /// <summary>
        /// Gets or sets the authorization endpoint.
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = OpenIdProviderMetadataNames.AuthorizationEndpoint, Required = Required.Default)]
        public string AuthorizationEndpoint { get; set; }

        /// <summary>
        /// Gets or sets the check_session_iframe.
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = OpenIdProviderMetadataNames.CheckSessionIframe, Required = Required.Default)]
        public string CheckSessionIframe { get; set; }

        /// <summary>
        /// Gets or sets the end session endpoint.
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = OpenIdProviderMetadataNames.EndSessionEndpoint, Required = Required.Default)]
        public string EndSessionEndpoint { get; set; }

        /// <summary>
        /// Gets the collection of 'id_token_signing_alg_values_supported'.
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = OpenIdProviderMetadataNames.IdTokenSigningAlgValuesSupported, Required = Required.Default)]
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
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = OpenIdProviderMetadataNames.Issuer, Required = Required.Default)]
        public string Issuer { get; set; }

        /// <summary>
        /// Gets or sets the 'jwks_uri'
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = OpenIdProviderMetadataNames.JwksUri, Required = Required.Default)]
        public string JwksUri{ get; set; }

        /// <summary>
        /// Gets or sets the <see cref="JsonWebKeySet"/>
        /// </summary>
        public JsonWebKeySet JsonWebKeySet {get; set;}

        /// <summary>
        /// Gets the collection of 'response_types_supported'.
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = OpenIdProviderMetadataNames.ResponseTypesSupported, Required = Required.Default)]
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
        /// Gets the collection of 'subject_types_supported'.
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = OpenIdProviderMetadataNames.SubjectTypesSupported, Required = Required.Default)]
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
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = OpenIdProviderMetadataNames.TokenEndpoint, Required = Required.Default)]
        public string TokenEndpoint { get; set; }

        /// <summary>
        /// Gets or sets the 'user_info_endpoint'.
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = OpenIdProviderMetadataNames.UserInfoEndpoint, Required = Required.Default)]
        public string UserInfoEndpoint { get; set; }
    }
}
