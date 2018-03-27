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
using System.Collections.ObjectModel;
using System.ComponentModel;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace Microsoft.IdentityModel.Protocols.OpenIdConnect
{
    /// <summary>
    /// Contains OpenIdConnect configuration that can be populated from a json string.
    /// </summary>
    [JsonObject]
    public class OpenIdConnectConfiguration
    {
        /// <summary>
        /// Deserializes the json string into an <see cref="OpenIdConnectConfiguration"/> object.
        /// </summary>
        /// <param name="json">json string representing the configuration.</param>
        /// <returns><see cref="OpenIdConnectConfiguration"/> object representing the configuration.</returns>
        /// <exception cref="ArgumentNullException">If 'json' is null or empty.</exception>
        /// <exception cref="ArgumentException">If 'json' fails to deserialize.</exception>
        public static OpenIdConnectConfiguration Create(string json)
        {
            if (string.IsNullOrEmpty(json))
                throw LogHelper.LogArgumentNullException(nameof(json));

            LogHelper.LogVerbose(LogMessages.IDX21808, json);
            return new OpenIdConnectConfiguration(json);
        }

        /// <summary>
        /// Serializes the <see cref="OpenIdConnectConfiguration"/> object to a json string.
        /// </summary>
        /// <param name="configuration"><see cref="OpenIdConnectConfiguration"/> object to serialize.</param>
        /// <returns>json string representing the configuration object.</returns>
        /// <exception cref="ArgumentNullException">If 'configuration' is null.</exception>
        public static string Write(OpenIdConnectConfiguration configuration)
        {
            if (configuration == null)
                throw LogHelper.LogArgumentNullException(nameof(configuration));

            LogHelper.LogVerbose(LogMessages.IDX21809);
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
        /// <exception cref="ArgumentNullException">If 'json' is null or empty.</exception>
        public OpenIdConnectConfiguration(string json)
        {
            if(string.IsNullOrEmpty(json))
                throw LogHelper.LogArgumentNullException(nameof(json));

            try
            {
                LogHelper.LogVerbose(LogMessages.IDX21806, json, this);
#if NET45 || NET451
                SetJsonParameters(json);
#else
                JsonConvert.PopulateObject(json, this);
#endif
            }
            catch (Exception ex)
            {
                throw LogHelper.LogExceptionMessage(new ArgumentException(LogHelper.FormatInvariant(LogMessages.IDX21815, json, GetType()), ex));
            }
        }

        private void SetJsonParameters(string json)
        {
            var jsonObj = JObject.Parse(json);
            foreach (var pair in jsonObj)
            {
                if (jsonObj.TryGetValue(pair.Key, out JToken value))
                {
                    SetParameter(pair.Key, value);
                }
            }
        }

        private void SetParameter(string key, JToken jToken)
        {
            if (key.Equals(OpenIdProviderMetadataNames.AcrValuesSupported, StringComparison.OrdinalIgnoreCase))
            {
                SetJArray(jToken, AcrValuesSupported);
            }
            else if (key.Equals(OpenIdProviderMetadataNames.AuthorizationEndpoint, StringComparison.OrdinalIgnoreCase))
            {
                AuthorizationEndpoint = jToken.ToString();
            }
            else if(key.Equals(OpenIdProviderMetadataNames.CheckSessionIframe, StringComparison.OrdinalIgnoreCase))
            {
                CheckSessionIframe = jToken.ToString();
            }
            else if(key.Equals(OpenIdProviderMetadataNames.ClaimsLocalesSupported, StringComparison.OrdinalIgnoreCase))
            {
                SetJArray(jToken, ClaimsLocalesSupported);
            }
            else if(key.Equals(OpenIdProviderMetadataNames.ClaimsParameterSupported, StringComparison.OrdinalIgnoreCase))
            {
                if (jToken.Type == JTokenType.Boolean)
                {
                    ClaimsParameterSupported = Convert.ToBoolean(jToken.ToString());
                }
            }
            else if(key.Equals(OpenIdProviderMetadataNames.ClaimsSupported, StringComparison.OrdinalIgnoreCase))
            {
                SetJArray(jToken, ClaimsSupported);
            }
            else if(key.Equals(OpenIdProviderMetadataNames.ClaimTypesSupported, StringComparison.OrdinalIgnoreCase))
            {
                SetJArray(jToken, ClaimTypesSupported);
            }
            else if(key.Equals(OpenIdProviderMetadataNames.DisplayValuesSupported, StringComparison.OrdinalIgnoreCase))
            {
                SetJArray(jToken, DisplayValuesSupported);
            }
            else if(key.Equals(OpenIdProviderMetadataNames.EndSessionEndpoint, StringComparison.OrdinalIgnoreCase))
            {
                EndSessionEndpoint = jToken.ToString();
            }
            else if(key.Equals(OpenIdProviderMetadataNames.FrontchannelLogoutSessionSupported, StringComparison.OrdinalIgnoreCase))
            {
                FrontchannelLogoutSessionSupported = jToken.ToString();
            }
            else if(key.Equals(OpenIdProviderMetadataNames.FrontchannelLogoutSupported, StringComparison.OrdinalIgnoreCase))
            {
                FrontchannelLogoutSupported = jToken.ToString();
            }
            else if(key.Equals(OpenIdProviderMetadataNames.HttpLogoutSupported, StringComparison.OrdinalIgnoreCase))
            {
                if (jToken.Type == JTokenType.Boolean)
                    HttpLogoutSupported = Convert.ToBoolean(jToken.ToString());
            }
            else if(key.Equals(OpenIdProviderMetadataNames.GrantTypesSupported, StringComparison.OrdinalIgnoreCase))
            {
                SetJArray(jToken, GrantTypesSupported);
            }
            else if(key.Equals(OpenIdProviderMetadataNames.IdTokenEncryptionAlgValuesSupported, StringComparison.OrdinalIgnoreCase))
            {
                SetJArray(jToken, IdTokenEncryptionAlgValuesSupported);
            }
            else if(key.Equals(OpenIdProviderMetadataNames.IdTokenEncryptionEncValuesSupported, StringComparison.OrdinalIgnoreCase))
            {
                SetJArray(jToken, IdTokenEncryptionEncValuesSupported);
            }
            else if(key.Equals(OpenIdProviderMetadataNames.IdTokenSigningAlgValuesSupported, StringComparison.OrdinalIgnoreCase))
            {
                SetJArray(jToken, IdTokenSigningAlgValuesSupported);
            }
            else if(key.Equals(OpenIdProviderMetadataNames.JwksUri, StringComparison.OrdinalIgnoreCase))
            {
                JwksUri = jToken.ToString();
            }
            else if(key.Equals(OpenIdProviderMetadataNames.Issuer, StringComparison.OrdinalIgnoreCase))
            {
                Issuer = jToken.ToString();
            }
            else if(key.Equals(OpenIdProviderMetadataNames.LogoutSessionSupported, StringComparison.OrdinalIgnoreCase))
            {
                LogoutSessionSupported = Convert.ToBoolean(jToken.ToString());
            }
            else if(key.Equals(OpenIdProviderMetadataNames.MicrosoftMultiRefreshToken, StringComparison.OrdinalIgnoreCase))
            {
                AdditionalData.Add(new KeyValuePair<string, object>(OpenIdProviderMetadataNames.MicrosoftMultiRefreshToken, Convert.ToBoolean(jToken.ToString())));
            }
            else if(key.Equals(OpenIdProviderMetadataNames.OpPolicyUri, StringComparison.OrdinalIgnoreCase))
            {
                OpPolicyUri = jToken.ToString();
            }
            else if(key.Equals(OpenIdProviderMetadataNames.OpTosUri, StringComparison.OrdinalIgnoreCase))
            {
                OpTosUri = jToken.ToString();
            }
            else if(key.Equals(OpenIdProviderMetadataNames.RegistrationEndpoint, StringComparison.OrdinalIgnoreCase))
            {
                RegistrationEndpoint = jToken.ToString();
            }
            else if(key.Equals(OpenIdProviderMetadataNames.RequestObjectEncryptionAlgValuesSupported, StringComparison.OrdinalIgnoreCase))
            {
                SetJArray(jToken, RequestObjectEncryptionAlgValuesSupported);
            }
            else if(key.Equals(OpenIdProviderMetadataNames.RequestObjectEncryptionEncValuesSupported, StringComparison.OrdinalIgnoreCase))
            {
                SetJArray(jToken, RequestObjectEncryptionEncValuesSupported);
            }
            else if(key.Equals(OpenIdProviderMetadataNames.RequestObjectSigningAlgValuesSupported, StringComparison.OrdinalIgnoreCase))
            {
                SetJArray(jToken, RequestObjectSigningAlgValuesSupported);
            }
            else if(key.Equals(OpenIdProviderMetadataNames.RequestParameterSupported, StringComparison.OrdinalIgnoreCase))
            {
                if (jToken.Type == JTokenType.Boolean)
                    RequestParameterSupported = Convert.ToBoolean(jToken.ToString());
            }
            else if(key.Equals(OpenIdProviderMetadataNames.RequestUriParameterSupported, StringComparison.OrdinalIgnoreCase))
            {
                if (jToken.Type == JTokenType.Boolean)
                    RequestUriParameterSupported = Convert.ToBoolean(jToken.ToString());
            }

            else if (key.Equals(OpenIdProviderMetadataNames.RequireRequestUriRegistration, StringComparison.OrdinalIgnoreCase))
            {
                if (jToken.Type == JTokenType.Boolean)
                    RequireRequestUriRegistration = Convert.ToBoolean(jToken.ToString());
            }
            else if(key.Equals(OpenIdProviderMetadataNames.ResponseModesSupported, StringComparison.OrdinalIgnoreCase))
            {
                SetJArray(jToken, ResponseModesSupported);
            }
            else if(key.Equals(OpenIdProviderMetadataNames.ResponseTypesSupported, StringComparison.OrdinalIgnoreCase))
            {
                SetJArray(jToken, ResponseTypesSupported);
            }
            else if (key.Equals(OpenIdProviderMetadataNames.ServiceDocumentation, StringComparison.OrdinalIgnoreCase))
            {
                ServiceDocumentation = jToken.ToString();
            }
            else if(key.Equals(OpenIdProviderMetadataNames.ScopesSupported, StringComparison.OrdinalIgnoreCase))
            {
                SetJArray(jToken, ScopesSupported);
            }
            else if (key.Equals(OpenIdProviderMetadataNames.SubjectTypesSupported, StringComparison.OrdinalIgnoreCase))
            {
                SetJArray(jToken, SubjectTypesSupported);
            }
            else if (key.Equals(OpenIdProviderMetadataNames.TokenEndpoint, StringComparison.OrdinalIgnoreCase))
            {
                TokenEndpoint = jToken.ToString();
            }
            else if(key.Equals(OpenIdProviderMetadataNames.TokenEndpointAuthMethodsSupported, StringComparison.OrdinalIgnoreCase))
            {
                SetJArray(jToken, TokenEndpointAuthMethodsSupported);
            }
            else if (key.Equals(OpenIdProviderMetadataNames.TokenEndpointAuthSigningAlgValuesSupported, StringComparison.OrdinalIgnoreCase))
            {
                SetJArray(jToken, TokenEndpointAuthSigningAlgValuesSupported);
            }
            else if (key.Equals(OpenIdProviderMetadataNames.UILocalesSupported, StringComparison.OrdinalIgnoreCase))
            {
                SetJArray(jToken, UILocalesSupported);
            }
            else if(key.Equals(OpenIdProviderMetadataNames.UserInfoEndpoint, StringComparison.OrdinalIgnoreCase))
            {
                UserInfoEndpoint = jToken.ToString();
            }
            else if(key.Equals(OpenIdProviderMetadataNames.UserInfoEncryptionAlgValuesSupported, StringComparison.OrdinalIgnoreCase))
            {
                SetJArray(jToken, UserInfoEndpointEncryptionAlgValuesSupported);
            }
            else if (key.Equals(OpenIdProviderMetadataNames.UserInfoEncryptionEncValuesSupported, StringComparison.OrdinalIgnoreCase))
            {
                SetJArray(jToken, UserInfoEndpointEncryptionEncValuesSupported); 
            }
            else if(key.Equals(OpenIdProviderMetadataNames.UserInfoSigningAlgValuesSupported, StringComparison.OrdinalIgnoreCase))
            {
                SetJArray(jToken, UserInfoEndpointSigningAlgValuesSupported);
            }
            else
            {
                AdditionalData.Add(new KeyValuePair<string, object>(key, jToken.ToString()));
            }
        }

        private void SetJArray(JToken jToken, ICollection<string> collection)
        {
            if (jToken.Type == JTokenType.Array)
            {
                foreach (var child in jToken.Children())
                    collection.Add(child.ToString());
            }
        }

        /// <summary>
        /// When deserializing from JSON any properties that are not defined will be placed here.
        /// </summary>
        [JsonExtensionData]
        public virtual IDictionary<string, object> AdditionalData { get; } = new Dictionary<string, object>();

        /// <summary>
        /// Gets the collection of 'acr_values_supported'
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = OpenIdProviderMetadataNames.AcrValuesSupported, Required = Required.Default)]
        public ICollection<string> AcrValuesSupported { get; } = new Collection<string>();

        /// <summary>
        /// Gets or sets the 'authorization_endpoint'.
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = OpenIdProviderMetadataNames.AuthorizationEndpoint, Required = Required.Default)]
        public string AuthorizationEndpoint { get; set; }

        /// <summary>
        /// Gets or sets the 'check_session_iframe'.
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = OpenIdProviderMetadataNames.CheckSessionIframe, Required = Required.Default)]
        public string CheckSessionIframe { get; set; }

        /// <summary>
        /// Gets the collection of 'claims_supported'
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = OpenIdProviderMetadataNames.ClaimsSupported, Required = Required.Default)]
        public ICollection<string> ClaimsSupported { get; } = new Collection<string>();

        /// <summary>
        /// Gets the collection of 'claims_locales_supported'
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = OpenIdProviderMetadataNames.ClaimsLocalesSupported, Required = Required.Default)]
        public ICollection<string> ClaimsLocalesSupported { get; } = new Collection<string>();

        /// <summary>
        /// Gets or sets the 'claims_parameter_supported'
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = OpenIdProviderMetadataNames.ClaimsParameterSupported, Required = Required.Default)]
        public bool ClaimsParameterSupported { get; set; }

        /// <summary>
        /// Gets the collection of 'claim_types_supported'
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = OpenIdProviderMetadataNames.ClaimTypesSupported, Required = Required.Default)]
        public ICollection<string> ClaimTypesSupported { get; } = new Collection<string>();

        /// <summary>
        /// Gets the collection of 'display_values_supported'
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = OpenIdProviderMetadataNames.DisplayValuesSupported, Required = Required.Default)]
        public ICollection<string> DisplayValuesSupported { get; } = new Collection<string>();

        /// <summary>
        /// Gets or sets the 'end_session_endpoint'.
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = OpenIdProviderMetadataNames.EndSessionEndpoint, Required = Required.Default)]
        public string EndSessionEndpoint { get; set; }

        /// <summary>
        /// Gets or sets the 'frontchannel_logout_session_supported'.
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = OpenIdProviderMetadataNames.FrontchannelLogoutSessionSupported, Required = Required.Default)]
        public string FrontchannelLogoutSessionSupported { get; set; }

        /// <summary>
        /// Gets or sets the 'frontchannel_logout_supported'.
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = OpenIdProviderMetadataNames.FrontchannelLogoutSupported, Required = Required.Default)]
        public string FrontchannelLogoutSupported { get; set; }

        /// <summary>
        /// Gets the collection of 'grant_types_supported'
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = OpenIdProviderMetadataNames.GrantTypesSupported, Required = Required.Default)]
        public ICollection<string> GrantTypesSupported { get; } = new Collection<string>();

        /// <summary>
        /// Boolean value specifying whether the OP supports HTTP-based logout. Default is false.
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = OpenIdProviderMetadataNames.HttpLogoutSupported, Required = Required.Default)]
        public bool HttpLogoutSupported { get; set; }

        /// <summary>
        /// Gets the collection of 'id_token_encryption_alg_values_supported'.
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = OpenIdProviderMetadataNames.IdTokenEncryptionAlgValuesSupported, Required = Required.Default)]
        public ICollection<string> IdTokenEncryptionAlgValuesSupported { get; } = new Collection<string>();

        /// <summary>
        /// Gets the collection of 'id_token_encryption_enc_values_supported'.
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = OpenIdProviderMetadataNames.IdTokenEncryptionEncValuesSupported, Required = Required.Default)]
        public ICollection<string> IdTokenEncryptionEncValuesSupported { get; } = new Collection<string>();

        /// <summary>
        /// Gets the collection of 'id_token_signing_alg_values_supported'.
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = OpenIdProviderMetadataNames.IdTokenSigningAlgValuesSupported, Required = Required.Default)]
        public ICollection<string> IdTokenSigningAlgValuesSupported { get; } = new Collection<string>();

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
        public ICollection<string> RequestObjectEncryptionAlgValuesSupported { get; } = new Collection<string>();

        /// <summary>
        /// Gets the collection of 'request_object_encryption_enc_values_supported'.
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = OpenIdProviderMetadataNames.RequestObjectEncryptionEncValuesSupported, Required = Required.Default)]
        public ICollection<string> RequestObjectEncryptionEncValuesSupported { get; } = new Collection<string>();

        /// <summary>
        /// Gets the collection of 'request_object_signing_alg_values_supported'.
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = OpenIdProviderMetadataNames.RequestObjectSigningAlgValuesSupported, Required = Required.Default)]
        public ICollection<string> RequestObjectSigningAlgValuesSupported { get; } = new Collection<string>();

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
        public ICollection<string> ResponseModesSupported { get; } = new Collection<string>();

        /// <summary>
        /// Gets the collection of 'response_types_supported'.
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = OpenIdProviderMetadataNames.ResponseTypesSupported, Required = Required.Default)]
        public ICollection<string> ResponseTypesSupported { get; } = new Collection<string>();

        /// <summary>
        /// Gets or sets the 'service_documentation'
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = OpenIdProviderMetadataNames.ServiceDocumentation, Required = Required.Default)]
        public string ServiceDocumentation { get; set; }

        /// <summary>
        /// Gets the collection of 'scopes_supported'
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = OpenIdProviderMetadataNames.ScopesSupported, Required = Required.Default)]
        public ICollection<string> ScopesSupported { get; } = new Collection<string>();

        /// <summary>
        /// Gets the <see cref="ICollection{SecurityKey}"/> that the IdentityProvider indicates are to be used signing tokens.
        /// </summary>
        public ICollection<SecurityKey> SigningKeys { get; } = new Collection<SecurityKey>();

        /// <summary>
        /// Gets the collection of 'subject_types_supported'.
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = OpenIdProviderMetadataNames.SubjectTypesSupported, Required = Required.Default)]
        public ICollection<string> SubjectTypesSupported { get; } = new Collection<string>();

        /// <summary>
        /// Gets or sets the 'token_endpoint'.
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = OpenIdProviderMetadataNames.TokenEndpoint, Required = Required.Default)]
        public string TokenEndpoint { get; set; }

        /// <summary>
        /// Gets the collection of 'token_endpoint_auth_methods_supported'.
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = OpenIdProviderMetadataNames.TokenEndpointAuthMethodsSupported, Required = Required.Default)]
        public ICollection<string> TokenEndpointAuthMethodsSupported { get; } = new Collection<string>();

        /// <summary>
        /// Gets the collection of 'token_endpoint_auth_signing_alg_values_supported'.
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = OpenIdProviderMetadataNames.TokenEndpointAuthSigningAlgValuesSupported, Required = Required.Default)]
        public ICollection<string> TokenEndpointAuthSigningAlgValuesSupported { get; } = new Collection<string>();

        /// <summary>
        /// Gets the collection of 'ui_locales_supported'
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = OpenIdProviderMetadataNames.UILocalesSupported, Required = Required.Default)]
        public ICollection<string> UILocalesSupported { get; } = new Collection<string>();

        /// <summary>
        /// Gets or sets the 'user_info_endpoint'.
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = OpenIdProviderMetadataNames.UserInfoEndpoint, Required = Required.Default)]
        public string UserInfoEndpoint { get; set; }

        /// <summary>
        /// Gets the collection of 'userinfo_encryption_alg_values_supported'
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = OpenIdProviderMetadataNames.UserInfoEncryptionAlgValuesSupported, Required = Required.Default)]
        public ICollection<string> UserInfoEndpointEncryptionAlgValuesSupported { get; } = new Collection<string>();

        /// <summary>
        /// Gets the collection of 'userinfo_encryption_enc_values_supported'
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = OpenIdProviderMetadataNames.UserInfoEncryptionEncValuesSupported, Required = Required.Default)]
        public ICollection<string> UserInfoEndpointEncryptionEncValuesSupported { get; } = new Collection<string>();

        /// <summary>
        /// Gets the collection of 'userinfo_signing_alg_values_supported'
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = OpenIdProviderMetadataNames.UserInfoSigningAlgValuesSupported, Required = Required.Default)]
        public ICollection<string> UserInfoEndpointSigningAlgValuesSupported { get; } = new Collection<string>();

#region shouldserialize
        /// <summary>
        /// Gets a bool that determines if the 'acr_values_supported' (AcrValuesSupported) property should be serialized.
        /// This is used by Json.NET in order to conditionally serialize properties.
        /// </summary>
        /// <return>true if 'acr_values_supported' (AcrValuesSupported) is not empty; otherwise, false.</return>
        [EditorBrowsable(EditorBrowsableState.Never)]
        public bool ShouldSerializeAcrValuesSupported()
        {
            return AcrValuesSupported.Count > 0;
        }

        /// <summary>
        /// Gets a bool that determines if the 'claims_supported' (ClaimsSupported) property should be serialized.
        /// This is used by Json.NET in order to conditionally serialize properties.
        /// </summary>
        /// <return>true if 'claims_supported' (ClaimsSupported) is not empty; otherwise, false.</return>
        [EditorBrowsable(EditorBrowsableState.Never)]
        public bool ShouldSerializeClaimsSupported()
        {
            return ClaimsSupported.Count > 0;
        }

        /// <summary>
        /// Gets a bool that determines if the 'claims_locales_supported' (ClaimsLocalesSupported) property should be serialized.
        /// This is used by Json.NET in order to conditionally serialize properties.
        /// </summary>
        /// <return>true if 'claims_locales_supported' (ClaimsLocalesSupported) is not empty; otherwise, false.</return>
        [EditorBrowsable(EditorBrowsableState.Never)]
        public bool ShouldSerializeClaimsLocalesSupported()
        {
            return ClaimsLocalesSupported.Count > 0;
        }

        /// <summary>
        /// Gets a bool that determines if the 'claim_types_supported' (ClaimTypesSupported) property should be serialized.
        /// This is used by Json.NET in order to conditionally serialize properties.
        /// </summary>
        /// <return>true if 'claim_types_supported' (ClaimTypesSupported) is not empty; otherwise, false.</return>
        [EditorBrowsable(EditorBrowsableState.Never)]
        public bool ShouldSerializeClaimTypesSupported()
        {
            return ClaimTypesSupported.Count > 0;
        }

        /// <summary>
        /// Gets a bool that determines if the 'display_values_supported' (DisplayValuesSupported) property should be serialized.
        /// This is used by Json.NET in order to conditionally serialize properties.
        /// </summary>
        /// <return>true if 'display_values_supported' (DisplayValuesSupported) is not empty; otherwise, false.</return>
        [EditorBrowsable(EditorBrowsableState.Never)]
        public bool ShouldSerializeDisplayValuesSupported()
        {
            return DisplayValuesSupported.Count > 0;
        }

        /// <summary>
        /// Gets a bool that determines if the 'grant_types_supported' (GrantTypesSupported) property should be serialized.
        /// This is used by Json.NET in order to conditionally serialize properties.
        /// </summary>
        /// <return>true if 'grant_types_supported' (GrantTypesSupported) is not empty; otherwise, false.</return>
        [EditorBrowsable(EditorBrowsableState.Never)]
        public bool ShouldSerializeGrantTypesSupported()
        {
            return GrantTypesSupported.Count > 0;
        }

        /// <summary>
        /// Gets a bool that determines if the 'id_token_encryption_alg_values_supported' (IdTokenEncryptionAlgValuesSupported) property should be serialized.
        /// This is used by Json.NET in order to conditionally serialize properties.
        /// </summary>
        /// <return>true if 'id_token_encryption_alg_values_supported' (IdTokenEncryptionAlgValuesSupported) is not empty; otherwise, false.</return>
        [EditorBrowsable(EditorBrowsableState.Never)]
        public bool ShouldSerializeIdTokenEncryptionAlgValuesSupported()
        {
            return IdTokenEncryptionAlgValuesSupported.Count > 0;
        }

        /// <summary>
        /// Gets a bool that determines if the 'id_token_encryption_enc_values_supported' (IdTokenEncryptionEncValuesSupported) property should be serialized.
        /// This is used by Json.NET in order to conditionally serialize properties.
        /// </summary>
        /// <return>true if 'id_token_encryption_enc_values_supported' (IdTokenEncryptionEncValuesSupported) is not empty; otherwise, false.</return>
        [EditorBrowsable(EditorBrowsableState.Never)]
        public bool ShouldSerializeIdTokenEncryptionEncValuesSupported()
        {
            return IdTokenEncryptionEncValuesSupported.Count > 0;
        }

        /// <summary>
        /// Gets a bool that determines if the 'id_token_signing_alg_values_supported' (IdTokenSigningAlgValuesSupported) property should be serialized.
        /// This is used by Json.NET in order to conditionally serialize properties.
        /// </summary>
        /// <return>true if 'id_token_signing_alg_values_supported' (IdTokenSigningAlgValuesSupported) is not empty; otherwise, false.</return>
        [EditorBrowsable(EditorBrowsableState.Never)]
        public bool ShouldSerializeIdTokenSigningAlgValuesSupported()
        {
            return IdTokenSigningAlgValuesSupported.Count > 0;
        }

        /// <summary>
        /// Gets a bool that determines if the 'request_object_encryption_alg_values_supported' (RequestObjectEncryptionAlgValuesSupported) property should be serialized.
        /// This is used by Json.NET in order to conditionally serialize properties.
        /// </summary>
        /// <return>true if 'request_object_encryption_alg_values_supported' (RequestObjectEncryptionAlgValuesSupported) is not empty; otherwise, false.</return>
        [EditorBrowsable(EditorBrowsableState.Never)]
        public bool ShouldSerializeRequestObjectEncryptionAlgValuesSupported()
        {
            return RequestObjectEncryptionAlgValuesSupported.Count > 0;
        }

        /// <summary>
        /// Gets a bool that determines if the 'request_object_encryption_enc_values_supported' (RequestObjectEncryptionEncValuesSupported) property should be serialized.
        /// This is used by Json.NET in order to conditionally serialize properties.
        /// </summary>
        /// <return>true if 'request_object_encryption_enc_values_supported' (RequestObjectEncryptionEncValuesSupported) is not empty; otherwise, false.</return>
        [EditorBrowsable(EditorBrowsableState.Never)]
        public bool ShouldSerializeRequestObjectEncryptionEncValuesSupported()
        {
            return RequestObjectEncryptionEncValuesSupported.Count > 0;
        }

        /// <summary>
        /// Gets a bool that determines if the 'request_object_signing_alg_values_supported' (RequestObjectSigningAlgValuesSupported) property should be serialized.
        /// This is used by Json.NET in order to conditionally serialize properties.
        /// </summary>
        /// <return>true if 'request_object_signing_alg_values_supported' (RequestObjectSigningAlgValuesSupported) is not empty; otherwise, false.</return>
        [EditorBrowsable(EditorBrowsableState.Never)]
        public bool ShouldSerializeRequestObjectSigningAlgValuesSupported()
        {
            return RequestObjectSigningAlgValuesSupported.Count > 0;
        }

        /// <summary>
        /// Gets a bool that determines if the 'response_modes_supported' (ResponseModesSupported) property should be serialized.
        /// This is used by Json.NET in order to conditionally serialize properties.
        /// </summary>
        /// <return>true if 'response_modes_supported' (ResponseModesSupported) is not empty; otherwise, false.</return>
        [EditorBrowsable(EditorBrowsableState.Never)]
        public bool ShouldSerializeResponseModesSupported()
        {
            return ResponseModesSupported.Count > 0;
        }

        /// <summary>
        /// Gets a bool that determines if the 'response_types_supported' (ResponseTypesSupported) property should be serialized.
        /// This is used by Json.NET in order to conditionally serialize properties.
        /// </summary>
        /// <return>true if 'response_types_supported' (ResponseTypesSupported) is not empty; otherwise, false.</return>
        [EditorBrowsable(EditorBrowsableState.Never)]
        public bool ShouldSerializeResponseTypesSupported()
        {
            return ResponseTypesSupported.Count > 0;
        }

        /// <summary>
        /// Gets a bool that determines if the 'scopes_supported' (ScopesSupported) property should be serialized.
        /// This is used by Json.NET in order to conditionally serialize properties.
        /// </summary>
        /// <return>true if 'scopes_supported' (ScopesSupported) is not empty; otherwise, false.</return>
        [EditorBrowsable(EditorBrowsableState.Never)]
        public bool ShouldSerializeScopesSupported()
        {
            return ScopesSupported.Count > 0;
        }

        /// <summary>
        /// Gets a bool that determines if the 'subject_types_supported' (SubjectTypesSupported) property should be serialized.
        /// This is used by Json.NET in order to conditionally serialize properties.
        /// </summary>
        /// <return>true if 'subject_types_supported' (SubjectTypesSupported) is not empty; otherwise, false.</return>
        [EditorBrowsable(EditorBrowsableState.Never)]
        public bool ShouldSerializeSubjectTypesSupported()
        {
            return SubjectTypesSupported.Count > 0;
        }

        /// <summary>
        /// Gets a bool that determines if the 'token_endpoint_auth_methods_supported' (TokenEndpointAuthMethodsSupported) property should be serialized.
        /// This is used by Json.NET in order to conditionally serialize properties.
        /// </summary>
        /// <return>true if 'token_endpoint_auth_methods_supported' (TokenEndpointAuthMethodsSupported) is not empty; otherwise, false.</return>
        [EditorBrowsable(EditorBrowsableState.Never)]
        public bool ShouldSerializeTokenEndpointAuthMethodsSupported()
        {
            return TokenEndpointAuthMethodsSupported.Count > 0;
        }

        /// <summary>
        /// Gets a bool that determines if the 'token_endpoint_auth_signing_alg_values_supported' (TokenEndpointAuthSigningAlgValuesSupported) property should be serialized.
        /// This is used by Json.NET in order to conditionally serialize properties.
        /// </summary>
        /// <return>true if 'token_endpoint_auth_signing_alg_values_supported' (TokenEndpointAuthSigningAlgValuesSupported) is not empty; otherwise, false.</return>
        [EditorBrowsable(EditorBrowsableState.Never)]
        public bool ShouldSerializeTokenEndpointAuthSigningAlgValuesSupported()
        {
            return TokenEndpointAuthSigningAlgValuesSupported.Count > 0;
        }

        /// <summary>
        /// Gets a bool that determines if the 'ui_locales_supported' (UILocalesSupported) property should be serialized.
        /// This is used by Json.NET in order to conditionally serialize properties.
        /// </summary>
        /// <return>true if 'ui_locales_supported' (UILocalesSupported) is not empty; otherwise, false.</return>
        [EditorBrowsable(EditorBrowsableState.Never)]
        public bool ShouldSerializeUILocalesSupported()
        {
            return UILocalesSupported.Count > 0;
        }

        /// <summary>
        /// Gets a bool that determines if the 'userinfo_encryption_alg_values_supported' (UserInfoEndpointEncryptionAlgValuesSupported ) property should be serialized.
        /// This is used by Json.NET in order to conditionally serialize properties.
        /// </summary>
        /// <return>true if 'userinfo_encryption_alg_values_supported' (UserInfoEndpointEncryptionAlgValuesSupported ) is not empty; otherwise, false.</return>
        [EditorBrowsable(EditorBrowsableState.Never)]
        public bool ShouldSerializeUserInfoEndpointEncryptionAlgValuesSupported()
        {
            return UserInfoEndpointEncryptionAlgValuesSupported.Count > 0;
        }

        /// <summary>
        /// Gets a bool that determines if the 'userinfo_encryption_enc_values_supported' (UserInfoEndpointEncryptionEncValuesSupported) property should be serialized.
        /// This is used by Json.NET in order to conditionally serialize properties.
        /// </summary>
        /// <return>true if 'userinfo_encryption_enc_values_supported' (UserInfoEndpointEncryptionEncValuesSupported) is not empty; otherwise, false.</return>
        [EditorBrowsable(EditorBrowsableState.Never)]
        public bool ShouldSerializeUserInfoEndpointEncryptionEncValuesSupported()
        {
            return UserInfoEndpointEncryptionEncValuesSupported.Count > 0;
        }

        /// <summary>
        /// Gets a bool that determines if the 'userinfo_signing_alg_values_supported' (UserInfoEndpointSigningAlgValuesSupported) property should be serialized.
        /// This is used by Json.NET in order to conditionally serialize properties.
        /// </summary>
        /// <return>true if 'userinfo_signing_alg_values_supported' (UserInfoEndpointSigningAlgValuesSupported) is not empty; otherwise, false.</return>
        [EditorBrowsable(EditorBrowsableState.Never)]
        public bool ShouldSerializeUserInfoEndpointSigningAlgValuesSupported()
        {
            return UserInfoEndpointSigningAlgValuesSupported.Count > 0;
        }

#endregion shouldserialize
    }
}
