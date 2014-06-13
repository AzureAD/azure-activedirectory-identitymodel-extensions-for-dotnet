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
using System.Collections;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Web.Script.Serialization;

namespace Microsoft.IdentityModel.Protocols
{
    /// <summary>
    /// Contains a collection of <see cref="JsonWebKey"/> that can be populated from a json string.
    /// </summary>
    /// <remarks>provides support for http://tools.ietf.org/html/draft-ietf-jose-json-web-key-27#section-5 </remarks>
    public class JsonWebKeySet
    {
        private static JavaScriptSerializer _javaScriptSerializer;

        // kept private to hide that a List is used public member returns IList.
        private List<JsonWebKey> _keys = new List<JsonWebKey>();

        static JsonWebKeySet()
        {
            _javaScriptSerializer = new JavaScriptSerializer();
        }

        /// <summary>
        /// Initializes an new instance of <see cref="JsonWebKeySet"/>.
        /// </summary>
        public JsonWebKeySet()
        {
        }

        /// <summary>
        /// Initializes an new instance of <see cref="JsonWebKeySet"/> from a json string.
        /// </summary>
        /// <param name="json">a json string containing values.</param>
        /// <exception cref="ArgumentNullException">if 'json' is null or whitespace.</exception>
        public JsonWebKeySet(string json)
        {
            if (string.IsNullOrWhiteSpace(json))
            {
                throw new ArgumentNullException("json");
            }

            SetFromDictionary(_javaScriptSerializer.Deserialize<Dictionary<string, object>>(json));
        }

        /// <summary>
        /// Creates an instance of <see cref="JsonWebKey"/>.
        /// </summary>
        /// <param name="dictionary">a dictionary containing a 'Keys' element which is a Dictionary of JsonWebKeys.</param>
        /// <exception cref="ArgumentNullExceptioni">if 'dictionary' is null.</exception>
        public JsonWebKeySet(IDictionary<string, object> dictionary)
        {
            if (dictionary == null)
            {
                throw new ArgumentNullException("dictionary");
            }

            SetFromDictionary(dictionary);
        }

        /// <summary>
        /// Gets the <see cref="IList{JsonWebKey}"/>.
        /// </summary>       
        public IList<JsonWebKey> Keys
        {
            get
            {
                return _keys;
            }
        }

        private void SetFromDictionary(IDictionary<string, object> dictionary)
        {
            object obj = null;
            if (!dictionary.TryGetValue(JsonWebKeyParameterNames.Keys, out obj))
            {
                throw new ArgumentException(ErrorMessages.IDX10800);
            }

            ArrayList keys = obj as ArrayList;
            if (keys != null)
            {
                foreach (var key in keys)
                {
                    _keys.Add(new JsonWebKey(key as Dictionary<string, object>));
                }
            }
         }
    }
}
