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
using System.IO;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace Microsoft.IdentityModel.Tokens
{
    internal class ECDsaAlgorithm
    {
#if NETSTANDARD1_4
        public ECDsa ecdsa;
#else
        public ECDsaCng ecdsaCng;
#endif
        public bool dispose;

        public static readonly Dictionary<string, int> DefaultECDsaKeySizeInBitsMap = new Dictionary<string, int>()
        {
            { SecurityAlgorithms.EcdsaSha256, 256 },
            { SecurityAlgorithms.EcdsaSha384, 384 },
            { SecurityAlgorithms.EcdsaSha512, 521 },
            { SecurityAlgorithms.EcdsaSha256Signature, 256 },
            { SecurityAlgorithms.EcdsaSha384Signature, 384 },
            { SecurityAlgorithms.EcdsaSha512Signature, 521 }
        };
    }

    internal class RsaAlgorithm
    {
#if NETSTANDARD1_4
        public RSA rsa;
#else
        public RSACryptoServiceProvider rsaCryptoServiceProvider;
        public RSACryptoServiceProviderProxy rsaCryptoServiceProviderProxy;
#endif
        public bool dispose;
    }

    /// <summary>
    /// Contains some utility methods.
    /// </summary>
    public static class Utility
    {
        /// <summary>
        /// A string with "empty" value.
        /// </summary>
        public const string Empty = "empty";

        /// <summary>
        /// A string with "null" value.
        /// </summary>
        public const string Null = "null";

        internal static byte[] Transform(ICryptoTransform transform, byte[] input, int inputOffset, int inputLength)
        {
            if (transform.CanTransformMultipleBlocks)
            {
                return transform.TransformFinalBlock(input, inputOffset, inputLength);
            }

            using (MemoryStream messageStream = new MemoryStream())
            using (CryptoStream cryptoStream =
                new CryptoStream(messageStream, transform, CryptoStreamMode.Write))
            {
                cryptoStream.Write(input, inputOffset, inputLength);
                cryptoStream.FlushFinalBlock();

                return messageStream.ToArray();
            }
        }

        /// <summary>
        /// Creates a copy of the byte array.
        /// </summary>
        /// <param name="src">The resource array.</param>
        /// <returns>A copy of the byte array.</returns>
        public static byte[] CloneByteArray(this byte[] src)
        {
            return (byte[])(src.Clone());
        }

        /// <summary>
        /// Serializes the list of strings into string as follows:
        /// 'str1','str2','str3' ...
        /// </summary>
        /// <param name="strings">
        /// The strings used to build a comma delimited string.
        /// </param>
        /// <returns>
        /// The single <see cref="string"/>.
        /// </returns>
        internal static string SerializeAsSingleCommaDelimitedString(IEnumerable<string> strings)
        {
            if (null == strings)
            {
                return Utility.Null;
            }

            StringBuilder sb = new StringBuilder();
            bool first = true;
            foreach (string str in strings)
            {
                if (first)
                {
                    sb.AppendFormat("{0}", str ?? Utility.Null);
                    first = false;
                }
                else
                {
                    sb.AppendFormat(", {0}", str ?? Utility.Null);
                }
            }

            if (first)
            {
                return Utility.Empty;
            }

            return sb.ToString();
        }

        /// <summary>
        /// Returns whether the input string is https.
        /// </summary>
        /// <param name="address">The input string.</param>
        /// <remarks>true if the input string is https; otherwise, false.</remarks>
        public static bool IsHttps(string address)
        {
            if (string.IsNullOrEmpty(address))
            {
                return false;
            }

            try
            {
                Uri uri = new Uri(address);
                return IsHttps(new Uri(address));
            }
            catch (UriFormatException)
            {
                return false;
            }

        }

        /// <summary>
        /// Returns whether the input uri is https.
        /// </summary>
        /// <param name="uri"><see cref="Uri"/>.</param>
        /// <returns>true if the input uri is https; otherwise, false.</returns>
        public static bool IsHttps(Uri uri)
        {
            if (uri == null)
            {
                return false;
            }
#if NETSTANDARD1_4
            return uri.Scheme.Equals("https", StringComparison.OrdinalIgnoreCase); //Uri.UriSchemeHttps is internal in dnxcore
#else
            return uri.Scheme.Equals(Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase);
#endif
        }

        /// <summary>
        /// Compares two byte arrays for equality. Hash size is fixed normally it is 32 bytes.
        /// The attempt here is to take the same time if an attacker shortens the signature OR changes some of the signed contents.
        /// </summary>
        /// <param name="a">
        /// One set of bytes to compare.
        /// </param>
        /// <param name="b">
        /// The other set of bytes to compare with.
        /// </param>
        /// <returns>
        /// true if the bytes are equal, false otherwise.
        /// </returns>
        [MethodImpl(MethodImplOptions.NoOptimization | MethodImplOptions.NoInlining)]
        public static bool AreEqual(byte[] a, byte[] b)
        {
            byte[] s_bytesA = new byte[] { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31 };
            byte[] s_bytesB = new byte[] { 31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0 };

            int result = 0;
            byte[] a1, a2;

            if (((null == a) || (null == b))
            || (a.Length != b.Length))
            {
                a1 = s_bytesA;
                a2 = s_bytesB;
            }
            else
            {
                a1 = a;
                a2 = b;
            }

            for (int i = 0; i < a1.Length; i++)
            {
                result |= a1[i] ^ a2[i];
            }

            return result == 0;
        }

        /// <summary>
        /// Compares two byte arrays for equality. Hash size is fixed normally it is 32 bytes.
        /// The attempt here is to take the same time if an attacker shortens the signature OR changes some of the signed contents.
        /// </summary>
        /// <param name="a">
        /// One set of bytes to compare.
        /// </param>
        /// <param name="b">
        /// The other set of bytes to compare with.
        /// </param>
        /// <param name="length">length of array to check</param>
        /// <returns>
        /// true if the bytes are equal, false otherwise.
        /// </returns>
        [MethodImpl(MethodImplOptions.NoOptimization | MethodImplOptions.NoInlining)]
        internal static bool AreEqual(byte[] a, byte[] b, int length)
        {
            byte[] s_bytesA = new byte[] { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31 };
            byte[] s_bytesB = new byte[] { 31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0 };

            int result = 0;
            int lenToUse = 0;
            byte[] a1, a2;

            if (((null == a) || (null == b))
            || (a.Length < length || b.Length < length))
            {
                a1 = s_bytesA;
                a2 = s_bytesB;
                lenToUse = a1.Length;
            }
            else
            {
                a1 = a;
                a2 = b;
                lenToUse = length;
            }

            for (int i = 0; i < lenToUse; i++)
            {
                result |= a1[i] ^ a2[i];
            }

            return result == 0;
        }

        internal static byte[] ConvertToBigEndian(long i)
        {
            byte[] temp = BitConverter.GetBytes(i);
            if (BitConverter.IsLittleEndian)
                Array.Reverse(temp);

            return temp;
        }

        internal static byte[] Xor(byte[] a, byte[] b, int offset, bool inPlace)
        {
            if (inPlace)
            {
                for (var i = 0; i < a.Length; i++)
                {
                    a[i] = (byte)(a[i] ^ b[offset + i]);
                }

                return a;
            }
            else
            {
                var result = new byte[a.Length];

                for (var i = 0; i < a.Length; i++)
                {
                    result[i] = (byte)(a[i] ^ b[offset + i]);
                }

                return result;
            }
        }

        internal static ECDsaAlgorithm ResolveECDsaAlgorithm(SecurityKey key, string algorithm, bool usePrivateKey)
        {
            if (key == null)
                return null;

            var ecdsaAlgorithm = new ECDsaAlgorithm();
            var ecdsaKey = key as ECDsaSecurityKey;

            if (ecdsaKey != null)
            {
#if NETSTANDARD1_4
                if (ecdsaKey.ECDsa != null && ValidateECDSAKeySize(ecdsaKey.ECDsa.KeySize, algorithm))
                {
                    ecdsaAlgorithm.ecdsa = ecdsaKey.ECDsa;
                    return ecdsaAlgorithm;
                }
#else // net451 windows
                if (ecdsaKey.ECDsa != null && ValidateECDSAKeySize(ecdsaKey.ECDsa.KeySize, algorithm))
                {
                    ecdsaAlgorithm.ecdsaCng = ecdsaKey.ECDsa as ECDsaCng;
                    return ecdsaAlgorithm;
                }
#endif
            }

            var webKey = key as JsonWebKey;
            if (webKey != null && webKey.Kty == JsonWebAlgorithmsKeyTypes.EllipticCurve)
            {
                ecdsaAlgorithm.dispose = true;
#if NETSTANDARD1_4
                ecdsaAlgorithm.ecdsa = webKey.CreateECDsa(algorithm, usePrivateKey);
#else // net451 windows
                ecdsaAlgorithm.ecdsaCng = webKey.CreateECDsa(algorithm, usePrivateKey);
#endif
                return ecdsaAlgorithm;
            }

            return null;
        }

        internal static RsaAlgorithm ResolveRsaAlgorithm(SecurityKey key, string algorithm, bool requirePrivateKey)
        {
            if (key == null)
                return null;

            var rsaAlgorithm = new RsaAlgorithm();
            var rsaKey = key as RsaSecurityKey;
            if (rsaKey != null)
            {
                if (rsaKey.Rsa != null)
                {
#if NETSTANDARD1_4
                    rsaAlgorithm.rsa = rsaKey.Rsa;
#else
                    rsaAlgorithm.rsaCryptoServiceProvider = rsaKey.Rsa as RSACryptoServiceProvider;
#endif
                    return rsaAlgorithm;
                }
                else
                {
#if NETSTANDARD1_4
                    rsaAlgorithm.rsa = RSA.Create();
                    rsaAlgorithm.rsa.ImportParameters(rsaKey.Parameters);
                    rsaAlgorithm.dispose = true;
#else
                    rsaAlgorithm.rsaCryptoServiceProvider = new RSACryptoServiceProvider();
                    (rsaAlgorithm.rsaCryptoServiceProvider as RSA).ImportParameters(rsaKey.Parameters);
                    rsaAlgorithm.dispose = true;
#endif
                }

                return rsaAlgorithm;
            }

            X509SecurityKey x509Key = key as X509SecurityKey;
            if (x509Key != null)
            {
#if NETSTANDARD1_4
                if (requirePrivateKey)
                    rsaAlgorithm.rsa = x509Key.PrivateKey as RSA;
                else
                    rsaAlgorithm.rsa = x509Key.PublicKey as RSA;
#else
                if (requirePrivateKey)
                    rsaAlgorithm.rsaCryptoServiceProviderProxy = new RSACryptoServiceProviderProxy(x509Key.PrivateKey as RSACryptoServiceProvider);
                else
                    rsaAlgorithm.rsaCryptoServiceProviderProxy = new RSACryptoServiceProviderProxy(x509Key.PublicKey as RSACryptoServiceProvider);
#endif
                return rsaAlgorithm;
            }

            JsonWebKey webKey = key as JsonWebKey;
            if (webKey != null && webKey.Kty == JsonWebAlgorithmsKeyTypes.RSA)
            {
#if NETSTANDARD1_4
                RSAParameters parameters = webKey.CreateRsaParameters();
                rsaAlgorithm.rsa = RSA.Create();
                rsaAlgorithm.dispose = true;
                if (rsaAlgorithm.rsa != null)
                    rsaAlgorithm.rsa.ImportParameters(parameters);
#else
                RSAParameters parameters = webKey.CreateRsaParameters();
                rsaAlgorithm.rsaCryptoServiceProvider = new RSACryptoServiceProvider();
                (rsaAlgorithm.rsaCryptoServiceProvider as RSA).ImportParameters(parameters);
#endif
                return rsaAlgorithm;
            }

            return null;
        }

        internal static bool ValidateECDSAKeySize(int keySize, string algorithm)
        {
            if (ECDsaAlgorithm.DefaultECDsaKeySizeInBitsMap.ContainsKey(algorithm) && keySize == ECDsaAlgorithm.DefaultECDsaKeySizeInBitsMap[algorithm])
                return true;

            return false;
        }

        internal static void Zero(byte[] byteArray)
        {
            for (var i = 0; i < byteArray.Length; i++)
            {
                byteArray[i] = 0;
            }
        }
    }
}
