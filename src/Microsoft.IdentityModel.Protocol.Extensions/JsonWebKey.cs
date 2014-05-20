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
using System.Collections.ObjectModel;
using System.Web.Script.Serialization;

namespace Microsoft.IdentityModel.Protocols
{
    /// <summary>
    /// Represents a Json Web Key as defined in http://tools.ietf.org/html/draft-ietf-jose-json-web-key-25.
    /// </summary>
    public class JsonWebKey
    {
        private static JavaScriptSerializer _javaScriptSerializer;

        // kept private to hide that a List is used.
        // public member returns an IList.
        private IList<string> _certificateClauses = new List<string>();

        static JsonWebKey()
        {
            _javaScriptSerializer = new JavaScriptSerializer();
        }

        /// <summary>
        /// Initializes an new instance of <see cref="JsonWebKey"/>.
        /// </summary>
        public JsonWebKey()
        {
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

            SetFromDictionary(_javaScriptSerializer.Deserialize<Dictionary<string, object>>(json));
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
                if (dictionary.TryGetValue(JsonWebKeysValueNames.Alg, out obj))
                {
                    str = obj as string;
                    if (str != null)
                    {
                        Alg = obj as string;
                    }
                }

                if (dictionary.TryGetValue(JsonWebKeysValueNames.KeyOps, out obj))
                {
                    str = obj as string;
                    if (str != null)
                    {
                        KeyOps = str;
                    }
                }

                if (dictionary.TryGetValue(JsonWebKeysValueNames.Kid, out obj))
                {
                    str = obj as string;
                    if (str != null)
                    {
                        Kid = str;
                    }
                }

                if (dictionary.TryGetValue(JsonWebKeysValueNames.Kty, out obj))
                {
                    str = obj as string;
                    if (str != null)
                    {
                        Kty = str;
                    }
                }

                if (dictionary.TryGetValue(JsonWebKeysValueNames.X5c, out obj))
                {
                    ArrayList jclauses = obj as ArrayList;
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

                if (dictionary.TryGetValue(JsonWebKeysValueNames.Kid, out obj))
                {
                    str = obj as string;
                    if (str != null)
                    {
                        X5t = str;
                    }
                }

                if (dictionary.TryGetValue(JsonWebKeysValueNames.X5u, out obj))
                {
                    str = obj as string;
                    if (str != null)
                    {
                        X5u = str;
                    }
                }

                if (dictionary.TryGetValue(JsonWebKeysValueNames.Use, out obj))
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
        public string Alg { get; set; }

        /// <summary>
        /// Gets or sets the 'key_ops' (Key Operations).
        /// </summary>
        public string KeyOps { get; set; }

        /// <summary>
        /// Gets or sets the 'kid' (Key ID).
        /// </summary>
        public string Kid { get; set; }

        /// <summary>
        /// Gets or sets the 'kty' (Key Type).
        /// </summary>
        public string Kty { get; set; }

        /// <summary>
        /// Gets the 'x5c' collection (X.509 Certificate Chain).
        /// </summary>
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
        public string X5t { get; set; }

        /// <summary>
        /// Gets or sets the 'x5u' (X.509 URL).
        /// </summary>
        public string X5u { get; set; }

        /// <summary>
        /// Gets or sets the 'use' (Public Key Use).
        /// </summary>       
        public string Use { get; set; }
    }
}