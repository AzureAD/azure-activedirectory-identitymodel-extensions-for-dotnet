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

using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IdentityModel.Tokens;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.IdentityModel.Logging;

namespace Microsoft.IdentityModel.Protocols
{
    /// <summary>
    /// Contains a collection of <see cref="JsonWebKey"/> that can be populated from a json string.
    /// </summary>
    /// <remarks>provides support for http://tools.ietf.org/html/draft-ietf-jose-json-web-key-27 </remarks>
    public class JsonWebKeySet
    {
        private List<JsonWebKey> _keys = new List<JsonWebKey>();

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
                LogHelper.LogError(string.Format(CultureInfo.InvariantCulture, ErrorMessages.IDX10000, GetType() + ": json"), typeof(ArgumentNullException));
            }

            try
            {
                IdentityModelEventSource.Logger.WriteVerbose("JsonWebKeySet.Constructor: Deserializing json string into json web keys.");
                var jwebKeys = JsonConvert.DeserializeObject<JsonWebKeySet>(json);
                _keys = jwebKeys._keys;
            }
            catch(Exception ex)
            {
                LogHelper.LogError(string.Format(CultureInfo.InvariantCulture, ErrorMessages.IDX10804, json), typeof(ArgumentException), ex);
            }
        }

        /// <summary>
        /// Creates an instance of <see cref="JsonWebKey"/>.
        /// </summary>
        /// <param name="dictionary">a dictionary containing a 'Keys' element which is a Dictionary of JsonWebKeys.</param>
        /// <exception cref="ArgumentNullException">if 'dictionary' is null.</exception>
        public JsonWebKeySet(IDictionary<string, object> dictionary)
        {
            if (dictionary == null)
            {
                LogHelper.LogError(string.Format(CultureInfo.InvariantCulture, ErrorMessages.IDX10000, GetType() + ": dictionary"), typeof(ArgumentNullException));
            }

            object obj = null;
            if (!dictionary.TryGetValue(JsonWebKeyParameterNames.Keys, out obj))
            {
                LogHelper.LogError(ErrorMessages.IDX10800, typeof(ArgumentException));
            }

            List<object> keys = obj as List<object>;
            if (keys != null)
            {
                foreach (var key in keys)
                {
                    Dictionary<string, object> dic = key as Dictionary<string, object>;
                    if (dic != null)
                        _keys.Add(new JsonWebKey(dic));
                }
            }
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

        /// <summary>
        /// Returns the JsonWebKeys as a <see cref="IList{SecurityKey}"/>.
        /// </summary>
        public IList<SecurityKey> GetSigningKeys()
        {
            List<SecurityKey> keys = new List<SecurityKey>();
            for (int i = 0; i < _keys.Count; i++)
            {
                JsonWebKey webKey = _keys[i];

                if (!StringComparer.Ordinal.Equals(webKey.Kty, JsonWebAlgorithmsKeyTypes.RSA))
                    continue;

                if ((string.IsNullOrWhiteSpace(webKey.Use) || (StringComparer.Ordinal.Equals(webKey.Use, JsonWebKeyUseNames.Sig))))
                {
                    if (webKey.X5c != null)
                    {
                        foreach (var certString in webKey.X5c)
                        {
                            try
                            {
                                // Add chaining
                                SecurityKey key = new X509SecurityKey(new X509Certificate2(Convert.FromBase64String(certString)));
                                key.KeyId = webKey.Kid;
                                keys.Add(key);
                            }
                            catch (CryptographicException ex)
                            {
                                LogHelper.LogError(string.Format(CultureInfo.InvariantCulture, ErrorMessages.IDX10802, webKey.X5c[0]), typeof(InvalidOperationException), ex);
                            }
                            catch (FormatException fex)
                            {
                                LogHelper.LogError(string.Format(CultureInfo.InvariantCulture, ErrorMessages.IDX10802, webKey.X5c[0]), typeof(InvalidOperationException), fex);
                            }
                        }
                    }

                    if (!string.IsNullOrWhiteSpace(webKey.E) && !string.IsNullOrWhiteSpace(webKey.N))
                    {
                        try
                        {
                            SecurityKey key =
                                 new RsaSecurityKey
                                 (
                                    new RSAParameters
                                    {
                                        Exponent = Base64UrlEncoder.DecodeBytes(webKey.E),
                                        Modulus = Base64UrlEncoder.DecodeBytes(webKey.N),
                                    }

                                );
                            key.KeyId = webKey.Kid;
                            keys.Add(key);
                        }
                        catch (CryptographicException ex)
                        {
                            LogHelper.LogError(string.Format(CultureInfo.InvariantCulture, ErrorMessages.IDX10801, webKey.E, webKey.N), typeof(InvalidOperationException), ex);
                        }
                        catch (FormatException ex)
                        {
                            LogHelper.LogError(string.Format(CultureInfo.InvariantCulture, ErrorMessages.IDX10801, webKey.E, webKey.N), typeof(InvalidOperationException), ex);
                        }
                    }
                }
            }

            return keys;
        }
    }
}
