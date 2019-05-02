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
using System.ComponentModel;
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
        public static JsonWebKeySet Create(string json)
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

        /// <summary>
        /// Initializes an new instance of <see cref="JsonWebKeySet"/> from a json string.
        /// </summary>
        /// <param name="json">a json string containing values.</param>
        /// <exception cref="ArgumentNullException">If 'json' is null or empty.</exception>
        /// <exception cref="ArgumentException">If 'json' fails to deserialize.</exception>
        public JsonWebKeySet(string json) : this(json, null)
        {
        }

        /// <summary>
        /// Initializes an new instance of <see cref="JsonWebKeySet"/> from a json string.
        /// </summary>
        /// <param name="json">a json string containing values.</param>
        /// <param name="jsonSerializerSettings">jsonSerializerSettings</param>
        /// <exception cref="ArgumentNullException">If 'json' is null or empty.</exception>
        /// <exception cref="ArgumentException">If 'json' fails to deserialize.</exception>
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
        /// Flag that controls whether invalid signing keys will be ignored during <see cref="GetSigningKeys"/> method execution.
        /// </summary>
        [DefaultValue(false)]
        public static bool IgnoreInvalidSigningKeys { get; set; } = false;

        /// <summary>
        /// Returns the JsonWebKeys as a <see cref="IList{SecurityKey}"/>.
        /// </summary>
        /// <remarks>
        /// To prevent this method from throwing exceptions for invalid signing keys set <see cref="IgnoreInvalidSigningKeys"/> to <c>true</c>.
        /// </remarks>
        public IList<SecurityKey> GetSigningKeys()
        {
            ECDsaAdapter ecdsaAdapter = null;
            var signingKeys = new List<SecurityKey>();

            foreach (var webKey in Keys)
            {
                // skip if "use" (Public Key Use) parameter is not empty or "sig"
                // https://tools.ietf.org/html/rfc7517#section-4.2
                if (!(string.IsNullOrWhiteSpace(webKey.Use) || webKey.Use.Equals(JsonWebKeyUseNames.Sig, StringComparison.Ordinal)))
                {
                    LogHelper.LogInformation(LogHelper.FormatInvariant(LogMessages.IDX10808, webKey.KeyId ?? "" , webKey.Use));
                    continue;
                }

                if (webKey.Kty != null && webKey.Kty.Equals(JsonWebAlgorithmsKeyTypes.RSA, StringComparison.Ordinal))
                {
                    var rsaKeyAdded = false;

                    if (webKey.X5c != null && webKey.X5c.Count != 0)
                    {
                        AddX509SecurityKey(signingKeys, webKey);
                        rsaKeyAdded = true;
                    }

                    if (!string.IsNullOrWhiteSpace(webKey.E) && !string.IsNullOrWhiteSpace(webKey.N))
                    {
                        AddRsaSecurityKey(signingKeys, webKey);
                        rsaKeyAdded = true;
                    }

                    if (!rsaKeyAdded)
                    {
                        // an rsa key was not resolved, but that doesn't mean that it's necessarily invalid.
                        LogHelper.LogInformation(LogHelper.FormatInvariant(LogMessages.IDX10810, webKey.KeyId ?? ""));
                        signingKeys.Add(webKey);
                    }
                }
                else if (webKey.Kty != null && webKey.Kty.Equals(JsonWebAlgorithmsKeyTypes.EllipticCurve, StringComparison.Ordinal))
                {
                    try
                    {
                        if (ecdsaAdapter == null)
                            ecdsaAdapter = new ECDsaAdapter();
                    }
                    catch (PlatformNotSupportedException)
                    {
                        // if a platform is not supported, add a key to signingKeys as a JsonWebKey.
                        LogHelper.LogInformation(LogHelper.FormatInvariant(LogMessages.IDX10690));
                        signingKeys.Add(webKey);
                        continue;
                    }

                    AddECDsaSecurityKey(signingKeys, webKey, ecdsaAdapter);
                }
                else
                {
                    // kty is not 'EC' or 'RSA', but that doesn't mean that a key it's necessarily invalid.
                    LogHelper.LogInformation(LogHelper.FormatInvariant(LogMessages.IDX10809, webKey.Kty ?? ""));
                    signingKeys.Add(webKey);
                }
            }

            return signingKeys;
        }

        private void AddX509SecurityKey(ICollection<SecurityKey> signingKeys, JsonWebKey jsonWebKey)
        {
            try
            {
                // only the first certificate should be used to perform signing operations
                // https://tools.ietf.org/html/rfc7517#section-4.7
                var x509SecurityKey =  new X509SecurityKey(new X509Certificate2(Convert.FromBase64String(jsonWebKey.X5c[0])))
                {
                    KeyId = jsonWebKey.Kid
                };

                signingKeys.Add(x509SecurityKey);
            }
            catch (Exception ex)
            {
                var exception = LogHelper.LogExceptionMessage(new InvalidOperationException(LogHelper.FormatInvariant(LogMessages.IDX10802, jsonWebKey.X5c[0], ex), ex));

                if (!IgnoreInvalidSigningKeys)
                    throw exception;
            }
        }

        private void AddRsaSecurityKey(ICollection<SecurityKey> signingKeys, JsonWebKey jsonWebKey)
        {
            try
            {
                var rsaParams = new RSAParameters
                {
                    Exponent = Base64UrlEncoder.DecodeBytes(jsonWebKey.E),
                    Modulus = Base64UrlEncoder.DecodeBytes(jsonWebKey.N),
                };

                var rsaSecurityKey = new RsaSecurityKey(rsaParams)
                {
                    KeyId = jsonWebKey.Kid
                };

                signingKeys.Add(rsaSecurityKey);
            }
            catch (Exception ex)
            {
                var exception = LogHelper.LogExceptionMessage(new InvalidOperationException(LogHelper.FormatInvariant(LogMessages.IDX10801, jsonWebKey.E, jsonWebKey.N, ex), ex));

                if (!IgnoreInvalidSigningKeys)
                    throw exception;
            }
        }

        private void AddECDsaSecurityKey(ICollection<SecurityKey> signingKeys, JsonWebKey jsonWebKey, ECDsaAdapter ecdsaAdapter)
        {
            try
            {
                var ecdsa = ecdsaAdapter.CreateECDsa(jsonWebKey, false);
                var ecdsaSecurityKey = new ECDsaSecurityKey(ecdsa)
                {
                    KeyId = jsonWebKey.Kid
                };

                signingKeys.Add(ecdsaSecurityKey);
            }
            catch (Exception ex)
            {
                var exception = LogHelper.LogExceptionMessage(new InvalidOperationException(LogHelper.FormatInvariant(LogMessages.IDX10807, ex), ex));

                if (!IgnoreInvalidSigningKeys)
                    throw exception;
            }
        }
    }
}
