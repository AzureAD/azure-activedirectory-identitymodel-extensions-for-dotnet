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
using System.Globalization;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
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
        /// <summary>
        /// Magic numbers identifying ECDSA blob types
        /// </summary>
        internal enum KeyBlobMagicNumber : uint
        {
            BCRYPT_ECDSA_PUBLIC_P256_MAGIC = 0x31534345,
            BCRYPT_ECDSA_PUBLIC_P384_MAGIC = 0x33534345,
            BCRYPT_ECDSA_PUBLIC_P521_MAGIC = 0x35534345,
            BCRYPT_ECDSA_PRIVATE_P256_MAGIC = 0x32534345,
            BCRYPT_ECDSA_PRIVATE_P384_MAGIC = 0x34534345,
            BCRYPT_ECDSA_PRIVATE_P521_MAGIC = 0x36534345,
        }

        /// <summary>
        /// Returns a new instance of <see cref="JsonWebKey"/>.
        /// </summary>
        /// <param name="json">A string that contains JSON Web Key parameters in JSON format.</param>
        /// <returns><see cref="JsonWebKey"/></returns>
        /// <exception cref="ArgumentNullException">If 'json' is null or empty.</exception>
        /// <exception cref="ArgumentException">If 'json' fails to deserialize.</exception>
        static public JsonWebKey Create(string json)
        {
            if (string.IsNullOrEmpty(json))
                throw LogHelper.LogArgumentNullException(nameof(json));

            return new JsonWebKey(json);
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
        /// <param name="json">A string that contains JSON Web Key parameters in JSON format.</param>
        /// <exception cref="ArgumentNullException">If 'json' is null or empty.</exception>
        /// <exception cref="ArgumentException">If 'json' fails to deserialize.</exception>
        public JsonWebKey(string json)
        {
            if (string.IsNullOrEmpty(json))
                throw LogHelper.LogArgumentNullException(nameof(json));

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
        /// <remarks>Value is formated as: Base64urlUInt</remarks>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = JsonWebKeyParameterNames.D, Required = Required.Default)]
        public string D { get; set; }

        /// <summary>
        /// Gets or sets the 'dp' (RSA - First Factor CRT Exponent)..
        /// </summary>
        /// <remarks>Value is formated as: Base64urlUInt</remarks>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = JsonWebKeyParameterNames.DP, Required = Required.Default)]
        public string DP { get; set; }

        /// <summary>
        /// Gets or sets the 'dq' (RSA - Second Factor CRT Exponent)..
        /// </summary>
        /// <remarks>Value is formated as: Base64urlUInt</remarks>
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
        /// Gets the 'key_ops' (Key Operations)..
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = JsonWebKeyParameterNames.KeyOps, Required = Required.Default)]
        public IList<string> KeyOps { get; private set; } = new List<string>();

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
        /// <remarks>Value is formated as: Base64urlEncoding</remarks>
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
        /// <remarks>Value is formated as: Base64urlUInt</remarks>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = JsonWebKeyParameterNames.P, Required = Required.Default)]
        public string P { get; set; }

        /// <summary>
        /// Gets or sets the 'q' (RSA - Second  Prime Factor)..
        /// </summary>
        /// <remarks>Value is formated as: Base64urlUInt</remarks>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = JsonWebKeyParameterNames.Q, Required = Required.Default)]
        public string Q { get; set; }

        /// <summary>
        /// Gets or sets the 'qi' (RSA - First CRT Coefficient)..
        /// </summary>
        /// <remarks>Value is formated as: Base64urlUInt</remarks>
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
        /// <remarks>Value is formated as: Base64urlEncoding</remarks>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = JsonWebKeyParameterNames.X, Required = Required.Default)]
        public string X { get; set; }

        /// <summary>
        /// Gets the 'x5c' collection (X.509 Certificate Chain)..
        /// </summary>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = JsonWebKeyParameterNames.X5c, Required = Required.Default)]
        public IList<string> X5c { get; private set; } = new List<string>();

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
        /// <remarks>Value is formated as: Base64urlEncoding</remarks>
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Ignore, NullValueHandling = NullValueHandling.Ignore, PropertyName = JsonWebKeyParameterNames.Y, Required = Required.Default)]
        public string Y { get; set; }

        /// <summary>
        /// Gets the key size of <see cref="JsonWebKey"/>.
        /// </summary>
        public override int KeySize
        {
            get
            {
                if (Kty == JsonWebAlgorithmsKeyTypes.RSA && !string.IsNullOrEmpty(N))
                    return Base64UrlEncoder.DecodeBytes(N).Length * 8;
                else if (Kty == JsonWebAlgorithmsKeyTypes.EllipticCurve && !string.IsNullOrEmpty(X))
                    return Base64UrlEncoder.DecodeBytes(X).Length * 8;
                else if (Kty == JsonWebAlgorithmsKeyTypes.Octet && !string.IsNullOrEmpty(K))
                    return Base64UrlEncoder.DecodeBytes(K).Length * 8;
                else
                    return 0;
            }
        }

        /// <summary>
        /// Gets a bool indicating if a private key exists.
        /// </summary>
        /// <return>true if it has a private key; otherwise, false.</return>
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

        internal ECDsaCng CreateECDsa(string algorithm, bool usePrivateKey)
        {
            if (Crv == null)
                throw LogHelper.LogArgumentNullException(nameof(Crv));

            if (X == null)
                throw LogHelper.LogArgumentNullException(nameof(X));

            if (Y == null)
                throw LogHelper.LogArgumentNullException(nameof(Y));

            GCHandle keyBlobHandle = new GCHandle();
            try
            {
                uint dwMagic = GetMagicValue(Crv, usePrivateKey);
                uint cbKey = GetKeyByteCount(Crv);
                byte[] keyBlob;
#if NET45
                if (usePrivateKey)
                    keyBlob = new byte[3 * cbKey + 2 * Marshal.SizeOf(typeof(uint))];
                else
                    keyBlob = new byte[2 * cbKey + 2 * Marshal.SizeOf(typeof(uint))];
#else
                 if (usePrivateKey)
                     keyBlob = new byte[3 * cbKey + 2 * Marshal.SizeOf<uint>()];
                 else
                     keyBlob = new byte[2 * cbKey + 2 * Marshal.SizeOf<uint>()];
#endif
                keyBlobHandle = GCHandle.Alloc(keyBlob, GCHandleType.Pinned);
                IntPtr keyBlobPtr = keyBlobHandle.AddrOfPinnedObject();
                byte[] x = Base64UrlEncoder.DecodeBytes(X);
                byte[] y = Base64UrlEncoder.DecodeBytes(Y);

                Marshal.WriteInt64(keyBlobPtr, 0, dwMagic);
                Marshal.WriteInt64(keyBlobPtr, 4, cbKey);

                int index = 8;
                foreach (byte b in x)
                    Marshal.WriteByte(keyBlobPtr, index++, b);

                foreach (byte b in y)
                    Marshal.WriteByte(keyBlobPtr, index++, b);

                if (usePrivateKey)
                {
                    if (D == null)
                        throw LogHelper.LogArgumentNullException(nameof(D));

                    byte[] d = Base64UrlEncoder.DecodeBytes(D);
                    foreach (byte b in d)
                        Marshal.WriteByte(keyBlobPtr, index++, b);

                    Marshal.Copy(keyBlobPtr, keyBlob, 0, keyBlob.Length);
                    using (CngKey cngKey = CngKey.Import(keyBlob, CngKeyBlobFormat.EccPrivateBlob))
                    {
                        if (Utility.ValidateECDSAKeySize(cngKey.KeySize, algorithm))
                            return new ECDsaCng(cngKey);
                        else
                            throw LogHelper.LogExceptionMessage(new ArgumentOutOfRangeException("key.KeySize", String.Format(CultureInfo.InvariantCulture, LogMessages.IDX10671, cngKey, ECDsaAlgorithm.DefaultECDsaKeySizeInBitsMap[algorithm], cngKey.KeySize)));
                    }
                }
                else
                {
                    Marshal.Copy(keyBlobPtr, keyBlob, 0, keyBlob.Length);
                    using (CngKey cngKey = CngKey.Import(keyBlob, CngKeyBlobFormat.EccPublicBlob))
                    {
                        if (Utility.ValidateECDSAKeySize(cngKey.KeySize, algorithm))
                            return new ECDsaCng(cngKey);
                        else
                            throw LogHelper.LogExceptionMessage(new ArgumentOutOfRangeException("key.KeySize", String.Format(CultureInfo.InvariantCulture, LogMessages.IDX10671, cngKey, ECDsaAlgorithm.DefaultECDsaKeySizeInBitsMap[algorithm], cngKey.KeySize)));
                    }
                }
            }
            finally
            {
                if (keyBlobHandle != null)
                    keyBlobHandle.Free();
            }
        }

        internal RSAParameters CreateRsaParameters()
        {
            if (N == null || E == null)
                throw LogHelper.LogExceptionMessage(new ArgumentException(String.Format(CultureInfo.InvariantCulture, LogMessages.IDX10700, this)));

            RSAParameters parameters = new RSAParameters();

            if (D != null)
                parameters.D = Base64UrlEncoder.DecodeBytes(D);

            if (DP != null)
                parameters.DP = Base64UrlEncoder.DecodeBytes(DP);

            if (DQ != null)
                parameters.DQ = Base64UrlEncoder.DecodeBytes(DQ);

            if (QI != null)
                parameters.InverseQ = Base64UrlEncoder.DecodeBytes(QI);

            if (P != null)
                parameters.P = Base64UrlEncoder.DecodeBytes(P);

            if (Q != null)
                parameters.Q = Base64UrlEncoder.DecodeBytes(Q);

            parameters.Exponent = Base64UrlEncoder.DecodeBytes(E);
            parameters.Modulus = Base64UrlEncoder.DecodeBytes(N);

            return parameters;
        }

        /// <summary>
        /// Returns the size of key in bytes
        /// </summary>
        /// <param name="curveId">Represents ecdsa curve -P256, P384, P521</param>
        /// <returns>Size of the key in bytes</returns>
        private uint GetKeyByteCount(string curveId)
        {
            if (string.IsNullOrEmpty(curveId))
                throw LogHelper.LogArgumentNullException(nameof(curveId));

            uint keyByteCount;
            switch (curveId)
            {
                case JsonWebKeyECTypes.P256:
                    keyByteCount = 32;
                    break;
                case JsonWebKeyECTypes.P384:
                    keyByteCount = 48;
                    break;
                case JsonWebKeyECTypes.P512: // treat 512 as 521. 512 doesn't exist, but we released with "512" instead of "521", so don't break now.
                case JsonWebKeyECTypes.P521:
                    keyByteCount = 64;
                    break;
                default:
                    throw LogHelper.LogExceptionMessage(new ArgumentException(String.Format(CultureInfo.InvariantCulture, LogMessages.IDX10645, curveId)));
            }
            return keyByteCount;
        }

        /// <summary>
        /// Returns the magic value representing the curve corresponding to the curve id.
        /// </summary>
        /// <param name="curveId">Represents ecdsa curve -P256, P384, P512</param>
        /// <param name="willCreateSignatures">Whether the provider will create signatures or not</param>
        /// <returns>Uint representing the magic number</returns>
        private uint GetMagicValue(string curveId, bool willCreateSignatures)
        {
            if (string.IsNullOrEmpty(curveId))
                throw LogHelper.LogArgumentNullException(nameof(curveId));

            KeyBlobMagicNumber magicNumber;
            switch (curveId)
            {
                case JsonWebKeyECTypes.P256:
                    if (willCreateSignatures)
                        magicNumber = KeyBlobMagicNumber.BCRYPT_ECDSA_PRIVATE_P256_MAGIC;
                    else
                        magicNumber = KeyBlobMagicNumber.BCRYPT_ECDSA_PUBLIC_P256_MAGIC;
                    break;
                case JsonWebKeyECTypes.P384:
                    if (willCreateSignatures)
                        magicNumber = KeyBlobMagicNumber.BCRYPT_ECDSA_PRIVATE_P384_MAGIC;
                    else
                        magicNumber = KeyBlobMagicNumber.BCRYPT_ECDSA_PUBLIC_P384_MAGIC;
                    break;
                case JsonWebKeyECTypes.P512: // treat 512 as 521. 512 doesn't exist, but we released with "512" instead of "521", so don't break now.
                case JsonWebKeyECTypes.P521:
                    if (willCreateSignatures)
                        magicNumber = KeyBlobMagicNumber.BCRYPT_ECDSA_PRIVATE_P521_MAGIC;
                    else
                        magicNumber = KeyBlobMagicNumber.BCRYPT_ECDSA_PUBLIC_P521_MAGIC;
                    break;
                default:
                    throw LogHelper.LogExceptionMessage(new ArgumentException(String.Format(CultureInfo.InvariantCulture, LogMessages.IDX10645, curveId)));
            }
            return (uint)magicNumber;
        }
    }
}
