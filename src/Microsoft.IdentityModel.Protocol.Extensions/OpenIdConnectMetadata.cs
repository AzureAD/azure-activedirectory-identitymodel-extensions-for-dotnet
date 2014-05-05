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

using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IdentityModel.Tokens;
using System.Web.Script.Serialization;

namespace Microsoft.IdentityModel.Protocols
{
    /// <summary>
    /// Contains OpenIdConnect metadata that can be populated from a json string.
    /// </summary>
    public class OpenIdConnectMetadata
    {
        private static JavaScriptSerializer _javaScriptSerializer;
        private Collection<SecurityToken> _signingTokens = new Collection<SecurityToken>();
        private Collection<JsonWebKey> _jsonWebKeys = new Collection<JsonWebKey>();

        static OpenIdConnectMetadata()
        {
            _javaScriptSerializer = new JavaScriptSerializer();
        }

        /// <summary>
        /// Initializes an new instance of <see cref="OpenIdConnectMetadata"/>.
        /// </summary>
        public OpenIdConnectMetadata()
        {           
        }

        /// <summary>
        /// Initializes an new instance of <see cref="OpenIdConnectMetadata"/> from a json string.
        /// </summary>
        /// <param name="json">a json string containing the metadata</param>
        public OpenIdConnectMetadata(string json)
        {
            if(string.IsNullOrWhiteSpace(json))
            {
                return;
            }

            SetFromDictionary(_javaScriptSerializer.Deserialize<Dictionary<string, object>>(json));
        }

        /// <summary>
        /// Initializes an new instance of <see cref="OpenIdConnectMetadata"/> from an <see cref="IDictionary[string, object]"/> string.
        /// </summary>
        /// <param name="dictionary">a <see cref="IDictionary[string, object]"/>jscontaining the metadata</param>
        public OpenIdConnectMetadata(IDictionary<string, object> dictionary)
        {
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
            if (dictionary.TryGetValue(OpenIdConnectMetadataNames.Authorization_Endpoint, out obj))
            {
                str = obj as string;
                if (str != null)
                {
                    Authorization_Endpoint = str;
                }
            }

            if (dictionary.TryGetValue(OpenIdConnectMetadataNames.Check_Session_Iframe, out obj))
            {
                str = dictionary[OpenIdConnectMetadataNames.Check_Session_Iframe] as string;
                if (str != null)
                {
                    Check_Session_Iframe = str;
                }
            }

            if (dictionary.TryGetValue(OpenIdConnectMetadataNames.End_Session_Endpoint, out obj))
            {
                str = obj as string;
                if (str != null)
                {
                    End_Session_Endpoint = str;
                }
            }

            if (dictionary.TryGetValue(OpenIdConnectMetadataNames.Issuer, out obj))
            {
                str = obj as string;
                if (str != null)
                {
                    Issuer = str;
                }
            }

            if (dictionary.TryGetValue(OpenIdConnectMetadataNames.Jwks_Uri, out obj))
            {
                str = obj as string;
                if (str != null)
                {
                    Jwks_Uri = str;
                }
            }

            if (dictionary.TryGetValue(OpenIdConnectMetadataNames.Token_Endpoint, out obj))
            {
                str = obj as string;
                if (str != null)
                {
                    Token_Endpoint = str;
                }
            }
        }

        /// <summary>
        /// Gets or sets the authorization endpoint.
        /// </summary>       
        public string Authorization_Endpoint { get; set; }

        /// <summary>
        /// Gets or sets the check_session_iframe.
        /// </summary>
        public string Check_Session_Iframe { get; set; }

        /// <summary>
        /// Gets or sets the end session endpoint.
        /// </summary>
        public string End_Session_Endpoint { get; set; }

        /// <summary>
        /// Gets or sets the token issuer.
        /// </summary>
        public string Issuer { get; set; }

        /// <summary>
        /// Gets or sets the token issuer.
        /// </summary>
        public string Jwks_Uri{ get; set; }

        /// <summary>
        /// Gets the JsonWebKeys
        /// </summary>
        public ICollection<JsonWebKey> JsonWebKeys
        {
            get
            {
                return _jsonWebKeys;
            }
        }

        /// <summary>
        /// Gets the collection of Signing tokens.
        /// </summary>
        public ICollection<SecurityToken> SigningTokens 
        { 
            get 
            {
                return _signingTokens; 
            } 
        }

        /// <summary>
        /// Gets or sets the token endpoint.
        /// </summary>
        public string Token_Endpoint { get; set; }
    }
}
