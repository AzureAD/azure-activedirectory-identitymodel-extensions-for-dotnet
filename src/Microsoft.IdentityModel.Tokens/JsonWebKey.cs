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
using Microsoft.IdentityModel.Logging;
using Newtonsoft.Json;

namespace Microsoft.IdentityModel.Tokens
{
    /// <summary>
    /// Represents a Json Web Key as defined in http://tools.ietf.org/html/rfc7517.
    /// </summary>
    [JsonObject]
    public class JsonWebKey : SecurityKey
    {
        // kept private to hide that a List is used.
        // public member returns an IList.
        private IList<string> _certificateClauses = new List<string>();
        private IList<string> _keyops = new List<string>();

        /// <summary>
        /// Returns a new instance of <see cref="JsonWebKey"/>.
        /// </summary>
        /// <param name="json">a string that contains JSON Web Key parameters in JSON format.</param>
        /// <returns><see cref="JsonWebKey"/></returns>
        /// <exception cref="ArgumentNullException">if 'json' is null or empty.</exception>
        static public JsonWebKey Create(string json)
        {
            if (string.IsNullOrEmpty(json))
                throw LogHelper.LogArgumentNullException("json");

            return JsonConvert.DeserializeObject<JsonWebKey>(json);
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
                throw LogHelper.LogArgumentNullException("json");

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
                _keyops = new List<string>(key.KeyOps);
            this.Kid = key.Kid;
            this.Kty = key.Kty;
            this.N = key.N;
            this.Oth = key.Oth;
            this.P = key.P;
            this.Q = key.Q;
            this.QI = key.QI;
            this.Use = key.Use;
            if (key.X5c != null)
                _certificateClauses = new List<string>(key.X5c);
            this.X5t = key.X5t;
            this.X5tS256 = key.X5tS256;
            this.X5u = key.X5u;
            this.X = key.X;
            this.Y = key.Y;
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
                    throw LogHelper.LogException<ArgumentNullException>(LogMessages.IDX10001, "KeyOps");

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

        /// <summary>
        /// Gets or sets the 'n' (RSA - Modulus)..
        /// </summary>
        /// <remarks> value is formated as: Base64urlEncoding</remarks>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = JsonWebKeyParameterNames.N, Required = Required.Default)]
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
                    throw LogHelper.LogException<ArgumentNullException>(LogMessages.IDX10001, "X5c");

                foreach (string clause in value)
                    _certificateClauses.Add(clause);
            }
        }

        /// <summary>
        /// Gets or sets the 'x5t' (X.509 Certificate SHA-1 thumbprint)..
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = JsonWebKeyParameterNames.X5t, Required = Required.Default)]
        public string X5t { get; set; }

        /// <summary>
        /// Gets or sets the 'x5t#S256' (X.509 Certificate SHA-1 thumbprint)..
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

        public override int KeySize
        {
            get
            {
                if (Kty == JsonWebAlgorithmsKeyTypes.RSA)
                    return Base64UrlEncoder.DecodeBytes(N).Length * 8;
                else if (Kty == JsonWebAlgorithmsKeyTypes.EllipticCurve)
                    return Base64UrlEncoder.DecodeBytes(X).Length * 8;
                else if (Kty == JsonWebAlgorithmsKeyTypes.Octet)
                    return Base64UrlEncoder.DecodeBytes(K).Length * 8;
                else
                    return 0;
            }
        }

        public bool HasPrivateKey
        {
            get
            {
                if (Kty == JsonWebAlgorithmsKeyTypes.RSA)
                    return D != null && DP != null && DQ != null && P != null && Q != null && QI != null;
                else if (Kty == JsonWebAlgorithmsKeyTypes.EllipticCurve)
                    return D != null;
                else
                    return false;
            }
        }
        public override SignatureProvider GetSignatureProvider(string algorithm, bool verifyOnly)
        {
            if (verifyOnly)
                return CryptoProviderFactory.CreateForVerifying(this, algorithm);
            else
                return CryptoProviderFactory.CreateForSigning(this, algorithm);
        }

        public override bool IsSupportedAlgorithm(string algorithm)
        {
            if (string.IsNullOrEmpty(algorithm))
                return false;

            if (Kty == JsonWebAlgorithmsKeyTypes.RSA)
            {
                switch (algorithm)
                {
                    case SecurityAlgorithms.RsaSha256:
                    case SecurityAlgorithms.RsaSha384:
                    case SecurityAlgorithms.RsaSha512:
                    case SecurityAlgorithms.RsaSha256Signature:
                    case SecurityAlgorithms.RsaSha384Signature:
                    case SecurityAlgorithms.RsaSha512Signature:
                        return true;

                    default:
                        return false;
                }
            }
            else if (Kty == JsonWebAlgorithmsKeyTypes.EllipticCurve)
            {
                switch (algorithm)
                {
                    case SecurityAlgorithms.EcdsaSha256:
                    case SecurityAlgorithms.EcdsaSha384:
                    case SecurityAlgorithms.EcdsaSha512:
                    case SecurityAlgorithms.EcdsaSha256Signature:
                    case SecurityAlgorithms.EcdsaSha384Signature:
                    case SecurityAlgorithms.EcdsaSha512Signature:
                        return true;

                    default:
                        return false;
                }
            }
            else if (Kty == JsonWebAlgorithmsKeyTypes.Octet)
            {
                switch (algorithm)
                {
                    case SecurityAlgorithms.HmacSha256Signature:
                    case SecurityAlgorithms.HmacSha384Signature:
                    case SecurityAlgorithms.HmacSha512Signature:
                    case SecurityAlgorithms.HmacSha256:
                    case SecurityAlgorithms.HmacSha384:
                    case SecurityAlgorithms.HmacSha512:
                        return true;

                    default:
                        return false;
                }
            }
            else
                return false;

        }
    }
}
