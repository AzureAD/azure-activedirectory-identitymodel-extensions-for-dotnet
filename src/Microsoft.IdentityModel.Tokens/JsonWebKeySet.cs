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
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.IdentityModel.Logging;
using Newtonsoft.Json;
using System.Globalization;

namespace Microsoft.IdentityModel.Tokens
{
    /// <summary>
    /// Contains a collection of <see cref="JsonWebKey"/> that can be populated from a json string.
    /// </summary>
    /// <remarks>provides support for http://tools.ietf.org/html/rfc7517.</remarks>
    [JsonObject]
    public class JsonWebKeySet
    {
        /// <summary>
        /// Returns a new instance of <see cref="JsonWebKeySet"/>.
        /// </summary>
        /// <param name="json">a string that contains JSON Web Key parameters in JSON format.</param>
        /// <returns><see cref="JsonWebKeySet"/></returns>
        /// <exception cref="ArgumentNullException">If 'json' is null or empty.</exception>
        /// <exception cref="ArgumentException">If 'json' fails to deserialize.</exception>
        static public JsonWebKeySet Create(string json)
        {
            if (string.IsNullOrEmpty(json))
                throw LogHelper.LogExceptionMessage(new ArgumentNullException(nameof(json), String.Format(CultureInfo.InvariantCulture, LogMessages.IDX10000, nameof(json)))); 

            return new JsonWebKeySet(json);
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
        /// <exception cref="ArgumentNullException">If 'json' is null or empty.</exception>
        /// <exception cref="ArgumentException">If 'json' fails to deserialize.</exception>
        public JsonWebKeySet(string json)
        {
            if (string.IsNullOrEmpty(json))
                throw LogHelper.LogExceptionMessage(new ArgumentNullException(nameof(json), String.Format(CultureInfo.InvariantCulture, LogMessages.IDX10000, nameof(json)))); 

            try
            {
                IdentityModelEventSource.Logger.WriteVerbose(LogMessages.IDX10806, json, this);
                JsonConvert.PopulateObject(json, this);
            }
            catch (Exception ex)
            {
                throw LogHelper.LogExceptionMessage(new ArgumentException(String.Format(CultureInfo.InvariantCulture, LogMessages.IDX10805, json, GetType()), ex));
            }
        }

        /// <summary>
        /// When deserializing from JSON any properties that are not defined will be placed here.
        /// </summary>
        [JsonExtensionData]
        public virtual IDictionary<string, object> AdditionalData { get; } = new Dictionary<string, object>();

        /// <summary>
        /// Gets the <see cref="IList{JsonWebKey}"/>.
        /// </summary>       
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = JsonWebKeySetParameterNames.Keys, Required = Required.Default)]
        public IList<JsonWebKey> Keys { get; } = new List<JsonWebKey>();

        /// <summary>
        /// Returns the JsonWebKeys as a <see cref="IList{SecurityKey}"/>.
        /// </summary>
        public IList<SecurityKey> GetSigningKeys()
        {
            List<SecurityKey> keys = new List<SecurityKey>();
            for (int i = 0; i < Keys.Count; i++)
            {
                JsonWebKey webKey = Keys[i];

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
                                throw LogHelper.LogExceptionMessage(new InvalidOperationException(String.Format(CultureInfo.InvariantCulture, LogMessages.IDX10802, webKey.X5c[0]), ex));
                            }
                            catch (FormatException fex)
                            {
                                throw LogHelper.LogExceptionMessage(new InvalidOperationException(String.Format(CultureInfo.InvariantCulture, LogMessages.IDX10802, webKey.X5c[0]), fex));
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
                            throw LogHelper.LogExceptionMessage(new InvalidOperationException(String.Format(CultureInfo.InvariantCulture, LogMessages.IDX10801, webKey.E, webKey.N), ex));
                        }
                        catch (FormatException ex)
                        {
                            throw LogHelper.LogExceptionMessage(new InvalidOperationException(String.Format(CultureInfo.InvariantCulture, LogMessages.IDX10801, webKey.E, webKey.N), ex));
                        }
                    }
                }
            }

            return keys;
        }
    }
}
