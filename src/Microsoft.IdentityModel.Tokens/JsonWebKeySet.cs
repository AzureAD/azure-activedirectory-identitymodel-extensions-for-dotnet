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
                throw LogHelper.LogArgumentNullException(nameof(json));

            return new JsonWebKeySet(json);
        }

        /// <summary>
        /// Initializes an new instance of <see cref="JsonWebKeySet"/>.
        /// </summary>
        public JsonWebKeySet()
        {
        }

#pragma warning disable CS0618 // Type or member is obsolete
        /// <summary>
        /// Initializes an new instance of <see cref="JsonWebKeySet"/> from a json string.
        /// </summary>
        /// <param name="json">a json string containing values.</param>
        /// <exception cref="ArgumentNullException">If 'json' is null or empty.</exception>
        /// <exception cref="ArgumentException">If 'json' fails to deserialize.</exception>
        public JsonWebKeySet(string json) : this(json, null)
        {
        }
#pragma warning restore CS0618 // Type or member is obsolete

        /// <summary>
        /// Initializes an new instance of <see cref="JsonWebKeySet"/> from a json string.
        /// </summary>
        /// <param name="json">a json string containing values.</param>
        /// <param name="jsonSerializerSettings">jsonSerializerSettings</param>
        /// <exception cref="ArgumentNullException">If 'json' is null or empty.</exception>
        /// <exception cref="ArgumentException">If 'json' fails to deserialize.</exception>
        [Obsolete("This constructor is obsolete and will be removed in a future release.")]
        public JsonWebKeySet(string json, JsonSerializerSettings jsonSerializerSettings)
        {
            if (string.IsNullOrEmpty(json))
                throw LogHelper.LogArgumentNullException(nameof(json));

            try
            {
                LogHelper.LogVerbose(LogMessages.IDX10806, json, this);
                if (jsonSerializerSettings != null)
                {
                    JsonConvert.PopulateObject(json, this, jsonSerializerSettings);
                }
                else
                {
                    JsonConvert.PopulateObject(json, this);
                }
            }
            catch (Exception ex)
            {
                throw LogHelper.LogExceptionMessage(new ArgumentException(LogHelper.FormatInvariant(LogMessages.IDX10805, json, GetType()), ex));
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
        public IList<JsonWebKey> Keys { get; private set; } = new List<JsonWebKey>();

        /// <summary>
        /// Returns the JsonWebKeys as a <see cref="IList{SecurityKey}"/>.
        /// </summary>
        public IList<SecurityKey> GetSigningKeys()
        {
            var signingKeys = new List<SecurityKey>();

            foreach (var webKey in Keys)
            {
                // skip if "use" (Public Key Use) parameter is not empty or "sig"
                if (!(string.IsNullOrWhiteSpace(webKey.Use) || webKey.Use.Equals(JsonWebKeyUseNames.Sig, StringComparison.Ordinal)))
                {
                    LogHelper.LogInformation(LogHelper.FormatInvariant(LogMessages.IDX10808, webKey.Use));
                    continue;
                }

                if (webKey.Kty.Equals(JsonWebAlgorithmsKeyTypes.RSA, StringComparison.Ordinal))
                {
                    if (webKey.X5c != null)
                        signingKeys.AddRange(CreateX509SecurityKeys(webKey));

                    if (!string.IsNullOrWhiteSpace(webKey.E) && !string.IsNullOrWhiteSpace(webKey.N))
                        signingKeys.Add(CreateRsaSecurityKey(webKey));
                }
                else if (webKey.Kty.Equals(JsonWebAlgorithmsKeyTypes.EllipticCurve, StringComparison.Ordinal))
                {
                    signingKeys.Add(CreateECDsaSecurityKey(webKey));
                }
                else
                {
                    //kty is not 'EC' or 'RSA'
                    LogHelper.LogInformation(LogHelper.FormatInvariant(LogMessages.IDX10809, webKey.Kty));
                }
            }

            return signingKeys;
        }

        private IList<SecurityKey> CreateX509SecurityKeys(JsonWebKey jsonWebKey)
        {
            try
            {
                var keys = new List<SecurityKey>();

                foreach (var certString in jsonWebKey.X5c)
                {
                    var key = new X509SecurityKey(new X509Certificate2(Convert.FromBase64String(certString)))
                    {
                        KeyId = jsonWebKey.Kid
                    };

                    keys.Add(key);
                }

                return keys;
            }
            catch (Exception ex)
            {
                throw LogHelper.LogExceptionMessage(new InvalidOperationException(LogHelper.FormatInvariant(LogMessages.IDX10802, jsonWebKey.X5c[0]), ex));
            }
        }

        private SecurityKey CreateRsaSecurityKey(JsonWebKey jsonWebKey)
        {
            try
            {
                var rsaParams = new RSAParameters
                {
                    Exponent = Base64UrlEncoder.DecodeBytes(jsonWebKey.E),
                    Modulus = Base64UrlEncoder.DecodeBytes(jsonWebKey.N),
                };

                return new RsaSecurityKey(rsaParams)
                {
                    KeyId = jsonWebKey.Kid
                };
            }
            catch (Exception ex)
            {
                throw LogHelper.LogExceptionMessage(new InvalidOperationException(LogHelper.FormatInvariant(LogMessages.IDX10801, jsonWebKey.E, jsonWebKey.N), ex));
            }
        }

        private SecurityKey CreateECDsaSecurityKey(JsonWebKey jsonWebKey)
        {
            try
            {
                var ecdsaAdapter = new ECDsaAdapter();
                var ecdsa = ecdsaAdapter.CreateECDsa(jsonWebKey, false);

                return new ECDsaSecurityKey(ecdsa)
                {
                    KeyId = jsonWebKey.Kid
                };
            }
            catch (Exception ex)
            {
                throw LogHelper.LogExceptionMessage(new InvalidOperationException(LogHelper.FormatInvariant(LogMessages.IDX10807), ex));
            }
        }
    }
}
