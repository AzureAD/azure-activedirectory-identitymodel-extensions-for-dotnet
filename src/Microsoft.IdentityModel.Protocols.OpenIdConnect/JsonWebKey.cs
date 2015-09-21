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
using System.Collections.Generic;
using System.Diagnostics.Tracing;
using System.Globalization;
using System.IdentityModel.Tokens;
using Microsoft.IdentityModel.Logging;
using Newtonsoft.Json;

namespace Microsoft.IdentityModel.Protocols.OpenIdConnect
{
    /// <summary>
    /// Represents a Json Web Key as defined in http://tools.ietf.org/html/draft-ietf-jose-json-web-key-37.
    /// </summary>

    [JsonObject]
    public class JsonWebKey
    {
        // kept private to hide that a List is used.
        // public member returns an IList.
        private IList<string> _certificateClauses = new List<string>();
        private IList<string> _keyops = new List<string>();

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
                LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10000, GetType() + ": json"), typeof(ArgumentNullException), EventLevel.Verbose);
            }

            var key = JsonConvert.DeserializeObject<JsonWebKey>(json);
            Copy(key);
        }

        private void Copy(JsonWebKey key)
        {
            this.Alg = key.Alg;
            this.Crv = key.Crv;
            this.D = key.D;
            this.DP = key.DP;
            this.DQ = key.DQ;
            this.E = key.E;
            this.K = key.K;
            if (key.KeyOps != null)
                this._keyops = new List<string>(key.KeyOps);
            this.Kid = key.Kid;
            this.Kty = key.Kty;
            this.N = key.N;
            this.Oth = key.Oth;
            this.P = key.P;
            this.Q = key.Q;
            this.QI = key.QI;
            this.Use = key.Use;
            if (key.X5c != null)
                this._certificateClauses = new List<string>(key.X5c);
            this.X5t = key.X5t;
            this.X5tS256 = key.X5tS256;
            this.X5u = key.X5u;
            this.X = key.X;
            this.Y = key.Y;
        }

        /// <summary>
        /// Creates an instance of <see cref="JsonWebKey"/>.
        /// </summary>
        /// <param name="dictionary"> that contains JSON Web Key parameters.</param>
        public JsonWebKey(IDictionary<string, object> dictionary)
        {
            if (dictionary == null)
            {
                LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10000, GetType() + ": dictionary"), typeof(ArgumentNullException), EventLevel.Verbose);
            }

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

            if (dictionary.TryGetValue(JsonWebKeyParameterNames.Crv, out obj))
            {
                str = obj as string;
                if (str != null)
                {
                    Crv = str;
                }
            }

            if (dictionary.TryGetValue(JsonWebKeyParameterNames.D, out obj))
            {
                str = obj as string;
                if (str != null)
                {
                    D = str;
                }
            }

            if (dictionary.TryGetValue(JsonWebKeyParameterNames.DP, out obj))
            {
                str = obj as string;
                if (str != null)
                {
                    DP = str;
                }
            }

            if (dictionary.TryGetValue(JsonWebKeyParameterNames.E, out obj))
            {
                str = obj as string;
                if (str != null)
                {
                    E = str;
                }
            }

            if (dictionary.TryGetValue(JsonWebKeyParameterNames.KeyOps, out obj))
            {
                IList<string> opts = obj as IList<string>;
                if (opts != null)
                {
                    KeyOps = opts;
                }
                else
                {
                    str = obj as string;
                    if (str != null)
                    {
                        _keyops.Add(str);
                    }
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
                    N = str;
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

        /// <summary>
        /// Gets or sets the 'alg' (KeyType)..
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = JsonWebKeyParameterNames.Alg, Required = Required.Default)]
        public string Alg { get; set; }

        /// <summary>
        /// Gets or sets the 'crv' (ECC - Curve)..
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = JsonWebKeyParameterNames.Crv, Required = Required.Default)]
        public string Crv { get; set; }

        /// <summary>
        /// Gets or sets the 'd' (ECC - Private Key OR RSA - Private Exponent)..
        /// </summary>
        /// <remarks> value is formated as: Base64urlUInt</remarks>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = JsonWebKeyParameterNames.D, Required = Required.Default)]
        public string D { get; set; }

        /// <summary>
        /// Gets or sets the 'dp' (RSA - First Factor CRT Exponent)..
        /// </summary>
        /// <remarks> value is formated as: Base64urlUInt</remarks>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = JsonWebKeyParameterNames.DP, Required = Required.Default)]
        public string DP { get; set; }

        /// <summary>
        /// Gets or sets the 'dq' (RSA - Second Factor CRT Exponent)..
        /// </summary>
        /// <remarks> value is formated as: Base64urlUInt</remarks>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = JsonWebKeyParameterNames.DQ, Required = Required.Default)]
        public string DQ { get; set; }

        /// <summary>
        /// Gets or sets the 'e' (RSA - Exponent)..
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = JsonWebKeyParameterNames.E, Required = Required.Default)]
        public string E { get; set; }
        /// <summary>
        /// Gets or sets the 'k' (Symmetric - Key Value)..
        /// </summary>
        /// Base64urlEncoding
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = JsonWebKeyParameterNames.K, Required = Required.Default)]
        public string K { get; set; }

        /// <summary>
        /// Gets or sets the 'key_ops' (Key Operations)..
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = JsonWebKeyParameterNames.KeyOps, Required = Required.Default)]
        public IList<string> KeyOps
        {
            get
            {
                return _keyops;
            }
            set
            {
                if (value == null)
                    LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10001, GetType() + ": KeyOps"), typeof(ArgumentNullException), EventLevel.Verbose);

                foreach (string keyOp in value)
                    _keyops.Add(keyOp);
            }
        }

        /// <summary>
        /// Gets or sets the 'kid' (Key ID)..
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = JsonWebKeyParameterNames.Kid, Required = Required.Default)]
        public string Kid { get; set; }

        /// <summary>
        /// Gets or sets the 'kty' (Key Type)..
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = JsonWebKeyParameterNames.Kty, Required = Required.Default)]
        public string Kty { get; set; }

        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = JsonWebKeyParameterNames.N, Required = Required.Default)]
        /// <summary>
        /// Gets or sets the 'n' (RSA - Modulus)..
        /// </summary>
        /// <remarks> value is formated as: Base64urlEncoding</remarks>
        public string N { get; set; }

        /// <summary>
        /// Gets or sets the 'oth' (RSA - Other Primes Info)..
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = JsonWebKeyParameterNames.Oth, Required = Required.Default)]
        public IList<string> Oth { get; set; }

        /// <summary>
        /// Gets or sets the 'p' (RSA - First Prime Factor)..
        /// </summary>
        /// <remarks> value is formated as: Base64urlUInt</remarks>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = JsonWebKeyParameterNames.P, Required = Required.Default)]
        public string P { get; set; }

        /// <summary>
        /// Gets or sets the 'q' (RSA - Second  Prime Factor)..
        /// </summary>
        /// <remarks> value is formated as: Base64urlUInt</remarks>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = JsonWebKeyParameterNames.Q, Required = Required.Default)]
        public string Q { get; set; }

        /// <summary>
        /// Gets or sets the 'qi' (RSA - First CRT Coefficient)..
        /// </summary>
        /// <remarks> value is formated as: Base64urlUInt</remarks>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = JsonWebKeyParameterNames.QI, Required = Required.Default)]
        public string QI { get; set; }

        /// <summary>
        /// Gets or sets the 'use' (Public Key Use)..
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = JsonWebKeyParameterNames.Use, Required = Required.Default)]
        public string Use { get; set; }

        /// <summary>
        /// Gets or sets the 'x' (ECC - X Coordinate)..
        /// </summary>
        /// <remarks> value is formated as: Base64urlEncoding</remarks>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = JsonWebKeyParameterNames.X, Required = Required.Default)]
        public string X { get; set; }

        /// <summary>
        /// Gets the 'x5c' collection (X.509 Certificate Chain)..
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = JsonWebKeyParameterNames.X5c, Required = Required.Default)]
        public IList<string> X5c
        {
            get
            {
                return _certificateClauses;
            }
            set
            {
                if (value == null)
                    LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, LogMessages.IDX10001, GetType() + ": X5c"), typeof(ArgumentNullException), EventLevel.Verbose);

                foreach (string clause in value)
                    _certificateClauses.Add(clause);
            }
        }

        /// <summary>
        /// Gets or sets the 'k5t' (X.509 Certificate SHA-1 thumbprint)..
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = JsonWebKeyParameterNames.X5t, Required = Required.Default)]
        public string X5t { get; set; }

        /// <summary>
        /// Gets or sets the 'k5t#S256' (X.509 Certificate SHA-1 thumbprint)..
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = JsonWebKeyParameterNames.X5tS256, Required = Required.Default)]
        public string X5tS256 { get; set; }

        /// <summary>
        /// Gets or sets the 'x5u' (X.509 URL)..
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = JsonWebKeyParameterNames.X5u, Required = Required.Default)]
        public string X5u { get; set; }

        /// <summary>
        /// Gets or sets the 'y' (ECC - Y Coordinate)..
        /// </summary>
        /// <remarks> value is formated as: Base64urlEncoding</remarks>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = JsonWebKeyParameterNames.Y, Required = Required.Default)]
        public string Y { get; set; }
    }
}