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

namespace Microsoft.IdentityModel.Protocols.OpenIdConnect
{
    /// <summary>
    /// Contains OpenIdConnect configuration that can be populated from a json string.
    /// </summary>
    [JsonObject]
    public class OpenIdConnectConfiguration
    {
        private Collection<string> _acrValuesSupported = new Collection<string>();
        private Collection<string> _claimsSupported = new Collection<string>();
        private Collection<string> _claimsLocalesSupported = new Collection<string>();
        private Collection<string> _claimTypesSupported = new Collection<string>();
        private Collection<string> _displayValuesSupported = new Collection<string>();
        private Collection<string> _grantTypesSupported = new Collection<string>();
        private Collection<string> _idTokenEncryptionAlgValuesSupported = new Collection<string>();
        private Collection<string> _idTokenEncryptionEncValuesSupported = new Collection<string>();
        private Collection<string> _idTokenSigningAlgValuesSupported = new Collection<string>();
        private Collection<string> _requestObjectEncryptionAlgValuesSupported = new Collection<string>();
        private Collection<string> _requestObjectEncryptionEncValuesSupported = new Collection<string>();
        private Collection<string> _requestObjectSigningAlgValuesSupported = new Collection<string>();
        private Collection<string> _responseModesSupported = new Collection<string>();
        private Collection<string> _responseTypesSupported = new Collection<string>();
        private Collection<SecurityKey> _signingKeys = new Collection<SecurityKey>();
        private Collection<string> _subjectTypesSupported = new Collection<string>();
        private Collection<string> _scopesSupported = new Collection<string>();
        private Collection<string> _tokenEndpointAuthMethodsSupported = new Collection<string>();
        private Collection<string> _tokenEndpointAuthSigningAlgValuesSupported = new Collection<string>();
        private Collection<string> _uiLocalesSupported = new Collection<string>();
        private Collection<string> _userinfoEncryptionAlgValuesSupported = new Collection<string>();
        private Collection<string> _userinfoEncryptionEncValuesSupported = new Collection<string>();
        private Collection<string> _userinfoSigningAlgValuesSupported = new Collection<string>();

        static OpenIdConnectConfiguration()
        {
        }

        /// <summary>
        /// Deserializes the json string into an <see cref="OpenIdConnectConfiguration"/> object.
        /// </summary>
        /// <param name="json">json string representing the configuration.</param>
        /// <returns><see cref="OpenIdConnectConfiguration"/> object representing the configuration.</returns>
        public static OpenIdConnectConfiguration Create(string json)
        {
            if (string.IsNullOrWhiteSpace(json))
            {
                LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, ErrorMessages.IDX10000, "OpenIdConnectConfiguration.Create: json"), typeof(ArgumentNullException), EventLevel.Verbose);
            }

            IdentityModelEventSource.Logger.WriteVerbose("Deserializing json into OpenIdConnectConfiguration object");
            return JsonConvert.DeserializeObject<OpenIdConnectConfiguration>(json);
        }

        /// <summary>
        /// Serializes the <see cref="OpenIdConnectConfiguration"/> object to a json string.
        /// </summary>
        /// <param name="configuration"><see cref="OpenIdConnectConfiguration"/> object to serialize.</param>
        /// <returns>json string representing the configuration object.</returns>
        public static string Write(OpenIdConnectConfiguration configuration)
        {
            if (configuration == null)
            {
                LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, ErrorMessages.IDX10000, "OpenIdConnectConfiguration.Write: configuration"), typeof(ArgumentNullException), EventLevel.Verbose);
            }

            IdentityModelEventSource.Logger.WriteVerbose("Serializing OpenIdConfiguration object to json string");
            return JsonConvert.SerializeObject(configuration);
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
            _acrValuesSupported = config._acrValuesSupported;
            AuthorizationEndpoint = config.AuthorizationEndpoint;
            CheckSessionIframe = config.CheckSessionIframe;
            _claimsSupported = config._claimsSupported;
            _claimsLocalesSupported = config._claimsLocalesSupported;
            ClaimsParameterSupported = config.ClaimsParameterSupported;
            _claimTypesSupported = config._claimTypesSupported;
            _displayValuesSupported = config._displayValuesSupported;
            EndSessionEndpoint = config.EndSessionEndpoint;
            _grantTypesSupported = config._grantTypesSupported;
            _idTokenEncryptionAlgValuesSupported = config._idTokenEncryptionAlgValuesSupported;
            _idTokenEncryptionEncValuesSupported = config._idTokenEncryptionEncValuesSupported;
            _idTokenSigningAlgValuesSupported = config._idTokenSigningAlgValuesSupported;
            Issuer = config.Issuer;
            JwksUri = config.JwksUri;
            JsonWebKeySet = config.JsonWebKeySet;
            OpPolicyUri = config.OpPolicyUri;
            OpTosUri = config.OpTosUri;
            RegistrationEndpoint = config.RegistrationEndpoint;
            RequireRequestUriRegistration = config.RequireRequestUriRegistration;
            _requestObjectEncryptionAlgValuesSupported = config._requestObjectEncryptionAlgValuesSupported;
            _requestObjectEncryptionEncValuesSupported = config._requestObjectEncryptionEncValuesSupported;
            _requestObjectSigningAlgValuesSupported = config._requestObjectSigningAlgValuesSupported;
            RequestParameterSupported = config.RequestParameterSupported;
            RequestUriParameterSupported = config.RequestUriParameterSupported;
            _responseModesSupported = config._responseModesSupported;
            _responseTypesSupported = config._responseTypesSupported;
            ServiceDocumentation = config.ServiceDocumentation;
            _scopesSupported = config._scopesSupported;
            _signingKeys = config._signingKeys;
            _subjectTypesSupported = config._subjectTypesSupported;
            TokenEndpoint = config.TokenEndpoint;
            _tokenEndpointAuthMethodsSupported = config._tokenEndpointAuthMethodsSupported;
            _tokenEndpointAuthSigningAlgValuesSupported = config._tokenEndpointAuthSigningAlgValuesSupported;
            UserInfoEndpoint = config.UserInfoEndpoint;
            _uiLocalesSupported = config._uiLocalesSupported;
            _userinfoEncryptionAlgValuesSupported = config._userinfoEncryptionAlgValuesSupported;
            _userinfoEncryptionEncValuesSupported = config._userinfoEncryptionEncValuesSupported;
            _userinfoSigningAlgValuesSupported = config._userinfoSigningAlgValuesSupported;
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
        /// Gets the collection of 'acr_values_supported'
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = OpenIdProviderMetadataNames.AcrValuesSupported, Required = Required.Default)]
        public ICollection<string> AcrValuesSupported
        {
            get
            {
                return _acrValuesSupported;
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
        /// Gets the collection of 'claims_supported'
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = OpenIdProviderMetadataNames.ClaimsSupported, Required = Required.Default)]
        public ICollection<string> ClaimsSupported
        {
            get
            {
                return _claimsSupported;
            }
        }

        /// <summary>
        /// Gets the collection of 'claims_locales_supported'
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = OpenIdProviderMetadataNames.ClaimsLocalesSupported, Required = Required.Default)]
        public ICollection<string> ClaimsLocalesSupported
        {
            get
            {
                return _claimsLocalesSupported;
            }
        }

        /// <summary>
        /// Gets or sets the 'claims_parameter_supported'
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = OpenIdProviderMetadataNames.ClaimsParameterSupported, Required = Required.Default)]
        public bool ClaimsParameterSupported { get; set; }

        /// <summary>
        /// Gets the collection of 'claim_types_supported'
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = OpenIdProviderMetadataNames.ClaimTypesSupported, Required = Required.Default)]
        public ICollection<string> ClaimTypesSupported
        {
            get
            {
                return _claimTypesSupported;
            }
        }

        /// <summary>
        /// Gets the collection of 'display_values_supported'
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = OpenIdProviderMetadataNames.DisplayValuesSupported, Required = Required.Default)]
        public ICollection<string> DisplayValuesSupported
        {
            get
            {
                return _displayValuesSupported;
            }
        }

        /// <summary>
        /// Gets or sets the end session endpoint.
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = OpenIdProviderMetadataNames.EndSessionEndpoint, Required = Required.Default)]
        public string EndSessionEndpoint { get; set; }

        /// <summary>
        /// Gets the collection of 'grant_types_supported'
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = OpenIdProviderMetadataNames.GrantTypesSupported, Required = Required.Default)]
        public ICollection<string> GrantTypesSupported
        {
            get
            {
                return _grantTypesSupported;
            }
        }

        /// <summary>
        /// Gets the collection of 'id_token_encryption_alg_values_supported'.
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = OpenIdProviderMetadataNames.IdTokenEncryptionAlgValuesSupported, Required = Required.Default)]
        public ICollection<string> IdTokenEncryptionAlgValuesSupported
        {
            get
            {
                return _idTokenEncryptionAlgValuesSupported;
            }
        }

        /// <summary>
        /// Gets the collection of 'id_token_encryption_enc_values_supported'.
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = OpenIdProviderMetadataNames.IdTokenEncryptionEncValuesSupported, Required = Required.Default)]
        public ICollection<string> IdTokenEncryptionEncValuesSupported
        {
            get
            {
                return _idTokenEncryptionEncValuesSupported;
            }
        }

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
        /// Gets or sets the 'op_policy_uri'
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = OpenIdProviderMetadataNames.OpPolicyUri, Required = Required.Default)]
        public string OpPolicyUri { get; set; }

        /// <summary>
        /// Gets or sets the 'op_tos_uri'
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = OpenIdProviderMetadataNames.OpTosUri, Required = Required.Default)]
        public string OpTosUri { get; set; }

        /// <summary>
        /// Gets or sets the 'registration_endpoint'
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = OpenIdProviderMetadataNames.RegistrationEndpoint, Required = Required.Default)]
        public string RegistrationEndpoint { get; set; }

        /// <summary>
        /// Gets the collection of 'request_object_encryption_alg_values_supported'.
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = OpenIdProviderMetadataNames.RequestObjectEncryptionAlgValuesSupported, Required = Required.Default)]
        public ICollection<string> RequestObjectEncryptionAlgValuesSupported
        {
            get
            {
                return _requestObjectEncryptionAlgValuesSupported;
            }
        }

        /// <summary>
        /// Gets the collection of 'request_object_encryption_enc_values_supported'.
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = OpenIdProviderMetadataNames.RequestObjectEncryptionEncValuesSupported, Required = Required.Default)]
        public ICollection<string> RequestObjectEncryptionEncValuesSupported
        {
            get
            {
                return _requestObjectEncryptionEncValuesSupported;
            }
        }

        /// <summary>
        /// Gets the collection of 'request_object_signing_alg_values_supported'.
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = OpenIdProviderMetadataNames.RequestObjectSigningAlgValuesSupported, Required = Required.Default)]
        public ICollection<string> RequestObjectSigningAlgValuesSupported
        {
            get
            {
                return _requestObjectSigningAlgValuesSupported;
            }
        }

        /// <summary>
        /// Gets or sets the 'request_parameter_supported'
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = OpenIdProviderMetadataNames.RequestParameterSupported, Required = Required.Default)]
        public bool RequestParameterSupported { get; set; }

        /// <summary>
        /// Gets or sets the 'request_uri_parameter_supported'
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = OpenIdProviderMetadataNames.RequestUriParameterSupported, Required = Required.Default)]
        public bool RequestUriParameterSupported { get; set; }

        /// <summary>
        /// Gets or sets the 'require_request_uri_registration'
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = OpenIdProviderMetadataNames.RequireRequestUriRegistration, Required = Required.Default)]
        public bool RequireRequestUriRegistration { get; set; }

        /// <summary>
        /// Gets the collection of 'response_modes_supported'.
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = OpenIdProviderMetadataNames.ResponseModesSupported, Required = Required.Default)]
        public ICollection<string> ResponseModesSupported
        {
            get
            {
                return _responseModesSupported;
            }
        }

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
        /// Gets or sets the 'service_documentation'
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = OpenIdProviderMetadataNames.ServiceDocumentation, Required = Required.Default)]
        public string ServiceDocumentation { get; set; }

        /// <summary>
        /// Gets the collection of 'scopes_supported'
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = OpenIdProviderMetadataNames.ScopesSupported, Required = Required.Default)]
        public ICollection<string> ScopesSupported
        {
            get
            {
                return _scopesSupported;
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
        /// Gets the collection of 'token_endpoint_auth_methods_supported'.
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = OpenIdProviderMetadataNames.TokenEndpointAuthMethodsSupported, Required = Required.Default)]
        public ICollection<string> TokenEndpointAuthMethodsSupported
        {
            get
            {
                return _tokenEndpointAuthMethodsSupported;
            }
        }

        /// <summary>
        /// Gets the collection of 'token_endpoint_auth_signing_alg_values_supported'.
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = OpenIdProviderMetadataNames.TokenEndpointAuthSigningAlgValuesSupported, Required = Required.Default)]
        public ICollection<string> TokenEndpointAuthSigningAlgValuesSupported
        {
            get
            {
                return _tokenEndpointAuthSigningAlgValuesSupported;
            }
        }

        /// <summary>
        /// Gets the collection of 'ui_locales_supported'
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = OpenIdProviderMetadataNames.UILocalesSupported, Required = Required.Default)]
        public ICollection<string> UILocalesSupported
        {
            get
            {
                return _uiLocalesSupported;
            }
        }

        /// <summary>
        /// Gets or sets the 'user_info_endpoint'.
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = OpenIdProviderMetadataNames.UserInfoEndpoint, Required = Required.Default)]
        public string UserInfoEndpoint { get; set; }

        /// <summary>
        /// Gets the collection of 'userinfo_encryption_alg_values_supported'
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = OpenIdProviderMetadataNames.UserInfoEncryptionAlgValuesSupported, Required = Required.Default)]
        public ICollection<string> UserInfoEndpointEncryptionAlgValuesSupported
        {
            get
            {
                return _userinfoEncryptionAlgValuesSupported;
            }
        }

        /// <summary>
        /// Gets the collection of 'userinfo_encryption_enc_values_supported'
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = OpenIdProviderMetadataNames.UserInfoEncryptionEncValuesSupported, Required = Required.Default)]
        public ICollection<string> UserInfoEndpointEncryptionEncValuesSupported
        {
            get
            {
                return _userinfoEncryptionEncValuesSupported;
            }
        }

        /// <summary>
        /// Gets the collection of 'userinfo_signing_alg_values_supported'
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = OpenIdProviderMetadataNames.UserInfoSigningAlgValuesSupported, Required = Required.Default)]
        public ICollection<string> UserInfoEndpointSigningAlgValuesSupported
        {
            get
            {
                return _userinfoSigningAlgValuesSupported;
            }
        }
    }
}
