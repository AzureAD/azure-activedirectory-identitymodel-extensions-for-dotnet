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

using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Tokens;
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
                throw LogHelper.LogArgumentNullException("json");

            IdentityModelEventSource.Logger.WriteVerbose(LogMessages.IDX10808, json);
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
                throw LogHelper.LogArgumentNullException("configuration");

            IdentityModelEventSource.Logger.WriteVerbose(LogMessages.IDX10809);
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
                throw LogHelper.LogArgumentNullException("json");

            OpenIdConnectConfiguration config = Create(json);
            Copy(config);
        }

        private void Copy(OpenIdConnectConfiguration config)
        {
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
            HttpLogoutSupported = config.HttpLogoutSupported;
            _idTokenEncryptionAlgValuesSupported = config._idTokenEncryptionAlgValuesSupported;
            _idTokenEncryptionEncValuesSupported = config._idTokenEncryptionEncValuesSupported;
            _idTokenSigningAlgValuesSupported = config._idTokenSigningAlgValuesSupported;
            Issuer = config.Issuer;
            JwksUri = config.JwksUri;
            JsonWebKeySet = config.JsonWebKeySet;
            LogoutSessionSupported = config.LogoutSessionSupported;
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
        /// Boolean value specifying whether the OP supports HTTP-based logout. Default is false.
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = OpenIdProviderMetadataNames.HttpLogoutSupported, Required = Required.Default)]
        public bool HttpLogoutSupported { get; set; }

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
        /// Boolean value specifying whether the OP can pass a sid (session ID) query parameter to identify the RP session at the OP when the logout_uri is used. Dafault Value is false.
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = OpenIdProviderMetadataNames.LogoutSessionSupported, Required = Required.Default)]
        public bool LogoutSessionSupported { get; set; }

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
