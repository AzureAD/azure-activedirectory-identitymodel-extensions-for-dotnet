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
using System.Web.Script.Serialization;

namespace Microsoft.IdentityModel.Protocols
{
    /// <summary>
    /// Contains a collection of <see cref="JsonWebKey"/> that can be populated from a json string.
    /// </summary>
    public class JsonWebKeys
    {
        private static JavaScriptSerializer _javaScriptSerializer;

        // kept private to hide that a List is used public member returns IList.
        private List<JsonWebKey> _keys = new List<JsonWebKey>();

        static JsonWebKeys()
        {
            _javaScriptSerializer = new JavaScriptSerializer();
        }

        /// <summary>
        /// Initializes an new instance of <see cref="JsonWebKeys"/>.
        /// </summary>
        public JsonWebKeys()
        {
        }

        /// <summary>
        /// Initializes an new instance of <see cref="JsonWebKeys"/> from a json string.
        /// </summary>
        /// <param name="json">a json string containing values.</param>
        public JsonWebKeys(string json)
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
        public JsonWebKeys(IDictionary<string, object> dictionary)
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
            if (dictionary.TryGetValue(JsonWebKeysValueNames.Keys, out obj))
            {
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

        /// <summary>
        /// Gets the list of 'keys' (Keys).
        /// </summary>       
        public IList<JsonWebKey> Keys
        {
            get
            {
                return _keys;
            }
        }
    }
}
