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
using System.Globalization;
using System.IdentityModel.Tokens;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Microsoft.IdentityModel.Protocols
{
    /// <summary>
    /// Contains a collection of <see cref="JsonWebKey"/> that can be populated from a json string.
    /// </summary>
    /// <remarks>provides support for http://tools.ietf.org/html/draft-ietf-jose-json-web-key-27#section-5 </remarks>
    public class JsonWebKeySet
    {
        private List<JsonWebKey> _keys = new List<JsonWebKey>();

        static JsonWebKeySet()
        {
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

            // TODO - brent, serializer
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

        /// <summary>
        /// Gets the Keys translated to <see cref="IList{SecurityToken}"/>.
        /// </summary>
        /// <returns>A <see cref="X509SecurityToken"/> for each 'X5c' that is composed from a single certificate. A NamedKeySecurityToken for each raw rsa public key.</returns>
        public IList<SecurityKey> GetSigningKeys()
        {
            List<SecurityKey> keys = new List<SecurityKey>();
            for (int i = 0; i < _keys.Count; i++)
            {
                JsonWebKey webKey = _keys[i];

                // create NamedSecurityToken for Kid'base64String, only RSA keys are supported.
                if (!StringComparer.Ordinal.Equals(webKey.Kty, JsonWebAlgorithmsKeyTypes.RSA))
                    continue;

                if ((string.IsNullOrWhiteSpace(webKey.Use) || (StringComparer.Ordinal.Equals(webKey.Use, JsonWebKeyUseNames.Sig))))
                {
                    if (webKey.X5c.Count == 1 && !string.IsNullOrWhiteSpace(webKey.X5c[0]))
                    {
                        try
                        {
                            // Add chaining
                            X509Certificate2 cert = new X509Certificate2(Convert.FromBase64String(webKey.X5c[0]));
                            if (!string.IsNullOrWhiteSpace(webKey.Kid))
                            {
                                // TODO, brent - figure out KID
                                //keys.Add(new X509SecurityKey(cert, webKey.Kid));
                                keys.Add(new X509SecurityKey(cert));
                            }
                            else
                            {
                                keys.Add(new X509SecurityKey(cert));
                            }
                        }
                        catch (CryptographicException ex)
                        {
                            throw new InvalidOperationException(string.Format(CultureInfo.InvariantCulture, ErrorMessages.IDX10802, webKey.X5c[0]), ex);
                        }
                        catch (FormatException fex)
                        {
                            throw new InvalidOperationException(string.Format(CultureInfo.InvariantCulture, ErrorMessages.IDX10802, webKey.X5c[0]), fex);
                        }
                    }

                    // only support public RSA
                    if (!string.IsNullOrWhiteSpace(webKey.E) && !string.IsNullOrWhiteSpace(webKey.N))
                    {
                        try
                        {
                            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
                            rsa.ImportParameters(
                                new RSAParameters
                                {
                                    Exponent = Base64UrlEncoder.DecodeBytes(webKey.E),
                                    Modulus = Base64UrlEncoder.DecodeBytes(webKey.N),
                                }
                            );

                            if (string.IsNullOrWhiteSpace(webKey.Kid))
                            {
                                // TODO, brent - figure out KID
                                //keys.Add(JsonWebKeyParameterNames.Kid, Guid.NewGuid().ToString(), new RsaSecurityKey(rsa)));
                                keys.Add(new RsaSecurityKey(rsa));
                            }
                            else
                            {
                                //keys.Add(new NamedKeySecurityToken(JsonWebKeyParameterNames.Kid, webKey.Kid, new RsaSecurityKey(rsa)));
                                keys.Add(new RsaSecurityKey(rsa));
                            }
                        }
                        catch (CryptographicException ex)
                        {
                            throw new InvalidOperationException(string.Format(CultureInfo.InvariantCulture, ErrorMessages.IDX10801, webKey.E, webKey.N), ex);
                        }
                        catch (FormatException ex)
                        {
                            throw new InvalidOperationException(string.Format(CultureInfo.InvariantCulture, ErrorMessages.IDX10801, webKey.E, webKey.N), ex);
                        }
                    }
                }
            }

            return keys;
        }

        private void SetFromDictionary(IDictionary<string, object> dictionary)
        {
            object obj = null;
            if (!dictionary.TryGetValue(JsonWebKeyParameterNames.Keys, out obj))
            {
                throw new ArgumentException(ErrorMessages.IDX10800);
            }

            List<object> keys = obj as List<object>;
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
