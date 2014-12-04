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

using System.Collections;
using System.Collections.Generic;
using System.IdentityModel.Tokens;
using Newtonsoft.Json;

namespace Microsoft.IdentityModel.Protocols
{
    /// <summary>
    /// Represents a Json Web Key as defined in http://tools.ietf.org/html/draft-ietf-jose-json-web-key-25.
    /// </summary>

    [JsonObject]
    public class JsonWebKey
    {
        // kept private to hide that a List is used.
        // public member returns an IList.
        private IList<string> _certificateClauses = new List<string>();

        /// <summary>
        /// Initializes an new instance of <see cref="JsonWebKey"/>.
        /// </summary>
        public JsonWebKey()
        {
        }

        static public JsonWebKey Create(string json)
        {
            return JsonConvert.DeserializeObject<JsonWebKey>(json);
        }

        /// <summary>
        /// Initializes an new instance of <see cref="JsonWebKey"/> from a json string.
        /// </summary>
        /// <param name="json">a string that contains JSON Web Key parameters in JSON format.</param>
        public JsonWebKey(string json)
        {
            if (string.IsNullOrWhiteSpace(json))
            {
                return;
            }

            // TODO - brent, serializer needs to be pluggable
            var key = JsonConvert.DeserializeObject<JsonWebKey>(json);
            Copy(key);
        }

        private void Copy(JsonWebKey key)
        {
            this.Alg = key.Alg;
            this.E = key.E;
            this.KeyOps = key.KeyOps;
            this.Kid = key.Kid;
            this.Kty = key.Kty;
            this.N = key.N;
            this.Use = key.Use;
            this._certificateClauses = key._certificateClauses;
            this.X5t = key.X5t;
            this.X5u = key.X5u;
        }

        /// <summary>
        /// Creates an instance of <see cref="JsonWebKey"/>.
        /// </summary>
        /// <param name="dictionary"> that contains JSON Web Key parameters.</param>
        public JsonWebKey(IDictionary<string, object> dictionary)
        {
            SetFromDictionary(dictionary);
        }

        private void SetFromDictionary(IDictionary<string, object> dictionary)
        {
            if (dictionary != null)
            {
                object obj = null;
                string str = null;
                if (dictionary.TryGetValue(JsonWebKeyParameterNames.Alg, out obj))
                {
                    str = obj as string;
                    if (str != null)
                    {
                        Alg = str;
                    }
                }

                if (dictionary.TryGetValue(JsonWebKeyParameterNames.E, out obj))
                {
                    str = obj as string;
                    if (str != null)
                    {
                    // TODO - brentsch, log an error if not right type
#if USE_STRINGS_FOR_RSA
                        E = str;
#else
                        E = Base64UrlEncoder.DecodeBytes(str);
#endif
                    }
                }

                if (dictionary.TryGetValue(JsonWebKeyParameterNames.KeyOps, out obj))
                {
                    str = obj as string;
                    if (str != null)
                    {
                        KeyOps = str;
                    }
                }

                if (dictionary.TryGetValue(JsonWebKeyParameterNames.Kid, out obj))
                {
                    str = obj as string;
                    if (str != null)
                    {
                        Kid = str;
                    }
                }

                if (dictionary.TryGetValue(JsonWebKeyParameterNames.Kty, out obj))
                {
                    str = obj as string;
                    if (str != null)
                    {
                        Kty = str;
                    }
                }

                if (dictionary.TryGetValue(JsonWebKeyParameterNames.N, out obj))
                {
                    str = obj as string;
                    if (str != null)
                    {
#if USE_STRINGS_FOR_RSA
                        N = str;
#else
                        N = Base64UrlEncoder.DecodeBytes(str);
#endif
                    }
                }

                if (dictionary.TryGetValue(JsonWebKeyParameterNames.X5c, out obj))
                {
                    List<object> jclauses = obj as List<object>;
                    if (jclauses != null)
                    {
                        foreach (var clause in jclauses)
                        {
                            _certificateClauses.Add(clause.ToString());
                        }
                    }
                    else
                    {
                        str = obj as string;
                        if (str != null)
                        {
                            _certificateClauses.Add(str);
                        }
                    }
                }

                if (dictionary.TryGetValue(JsonWebKeyParameterNames.X5t, out obj))
                {
                    str = obj as string;
                    if (str != null)
                    {
                        X5t = str;
                    }
                }

                if (dictionary.TryGetValue(JsonWebKeyParameterNames.X5u, out obj))
                {
                    str = obj as string;
                    if (str != null)
                    {
                        X5u = str;
                    }
                }

                if (dictionary.TryGetValue(JsonWebKeyParameterNames.Use, out obj))
                {
                    str = obj as string;
                    if (str != null)
                    {
                        Use = str;
                    }
                }
            }
        }

        /// <summary>
        /// Gets or sets the 'alg' (KeyType).
        /// </summary>       
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = JsonWebKeyParameterNames.Alg, Required = Required.Default)]
        public string Alg { get; set; }

        /// <summary>
        /// Gets or sets the E 'e'
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = JsonWebKeyParameterNames.E, Required = Required.Default)]
#if USE_STRINGS_FOR_RSA
        public string E { get; set; }
#else
        [JsonConverter(typeof(Base64UrlConverter))]
        public byte[] E { get; set; }

#endif
        /// <summary>
        /// Gets or sets the 'key_ops' (Key Operations).
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = JsonWebKeyParameterNames.KeyOps, Required = Required.Default)]
        public string KeyOps { get; set; }

        /// <summary>
        /// Gets or sets the 'kid' (Key ID).
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = JsonWebKeyParameterNames.Kid, Required = Required.Default)]
        public string Kid { get; set; }

        /// <summary>
        /// Gets or sets the 'kty' (Key Type).
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = JsonWebKeyParameterNames.Kty, Required = Required.Default)]
        public string Kty { get; set; }

        // RSA modulus, in Base64.
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = JsonWebKeyParameterNames.N, Required = Required.Default)]
#if USE_STRINGS_FOR_RSA
        public string N { get; set; }
#else
        [JsonConverter( typeof( Base64UrlConverter ) )]
        public byte[] N { get; set; }
#endif
        /// <summary>
        /// Gets or sets the 'use' (Public Key Use).
        /// </summary>       
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = JsonWebKeyParameterNames.Use, Required = Required.Default)]
        public string Use { get; set; }

        /// <summary>
        /// Gets the 'x5c' collection (X.509 Certificate Chain).
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = JsonWebKeyParameterNames.X5c, Required = Required.Default)]
        public IList<string> X5c
        {
            get
            {
                return _certificateClauses;
            }
        }

        /// <summary>
        /// Gets or sets the 'k5t' (X.509 Certificate SHA-1 thumbprint).
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = JsonWebKeyParameterNames.X5t, Required = Required.Default)]
        public string X5t { get; set; }

        /// <summary>
        /// Gets or sets the 'x5u' (X.509 URL).
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = JsonWebKeyParameterNames.X5u, Required = Required.Default)]
        public string X5u { get; set; }
    }
}