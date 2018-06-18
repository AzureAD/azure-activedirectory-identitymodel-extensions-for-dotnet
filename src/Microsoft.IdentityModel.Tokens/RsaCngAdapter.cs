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
using System.Reflection;
using System.Security.Cryptography;

namespace Microsoft.IdentityModel.Tokens
{
#if !NETSTANDARD1_4
    internal class RsaCngAdapter
    {
        private const string HashAlgorithmNameTypeName = "System.Security.Cryptography.HashAlgorithmName";
        private const string RSASignaturePaddingTypeName = "System.Security.Cryptography.RSASignaturePadding";
        private const string RSACngTypeName = "System.Security.Cryptography.RSACng";
        private const string DSACngTypeName = "System.Security.Cryptography.DSACng";

        private static volatile Func<RSA, byte[], string, byte[]> s_rsaPkcs1SignMethod;
        private static volatile Func<RSA, byte[], byte[], string, bool> s_rsaPkcs1VerifyMethod;
        private static Type s_hashAlgorithmNameType = typeof(object).Assembly.GetType(HashAlgorithmNameTypeName, false);
        private static Type s_rsaSignaturePaddingType = typeof(object).Assembly.GetType(RSASignaturePaddingTypeName, false);

        internal RsaCngAdapter(RSA rsa)
        {
            RSA = rsa;
        }

        internal RSA RSA { get; private set; }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="namespaceQualifiedTypeName"></param>
        /// <param name="throwOnError"></param>
        /// <returns></returns>
        internal static Type GetSystemCoreType(string namespaceQualifiedTypeName, bool throwOnError = true)
        {
            Assembly systemCore = typeof(CngKey).Assembly;
            return systemCore.GetType(namespaceQualifiedTypeName, throwOnError);
        }

        /// <summary>
        /// Detects if RSACng is available
        /// </summary>
        /// <returns></returns>
        internal static bool IsRsaCngSupported()
        {
            Type rsaCng = GetSystemCoreType(RSACngTypeName, throwOnError: false);

            // If the type doesn't exist, there can't be good support for it.
            // (System.Core < 4.6)
            if (rsaCng == null)
                return false;

            Type dsaCng = GetSystemCoreType(DSACngTypeName, throwOnError: false);

            // The original implementation of RSACng returned shared objects in the CAPI fallback
            // pathway. That behavior is hard to test for, since CNG can load all CAPI software keys.
            // But, since DSACng was added in 4.6.2, and RSACng better guarantees uniqueness in 4.6.2
            // use that coincidence as a compatibility test.
            //
            // If DSACng is missing, RSACng usage might lead to attempting to use Disposed objects
            // (System.Core < 4.6.2)
            if (dsaCng == null)
                return false;

            // Create an RSACng instance and send it to RSAPKCS1KeyExchangeFormatter. It was adjusted to
            // be CNG-capable for 4.6.2; and other types in that library also are up-to-date.
            //
            // If mscorlib can't handle it properly, then other libraries probably can't, so we'll keep
            // preferring RSACryptoServiceProvider.
            RSA rsa = (RSA)Activator.CreateInstance(rsaCng);
            try
            {
                RSAPKCS1KeyExchangeFormatter formatter = new RSAPKCS1KeyExchangeFormatter(rsa);
                formatter.CreateKeyExchange(new byte[1]);
            }
            catch (Exception)
            {
                // (mscorlib < 4.6.2)
                return false;
            }

            return true;
        }

        internal byte[] Pkcs1SignData(byte[] input, string hashAlgorithmName)
        {
            if (s_rsaPkcs1SignMethod == null)
            {
                // [X] SignData(byte[] data, HashAlgorithmName hashAlgorithmName, RSASignaturePadding padding)
                // [ ] SignData(byte[] data, int offset, int count, HashAlgorithmName hashAlgorithmName, RSASignaturePadding padding)
                // [ ] SignData(Stream data, HashAlgorithmName hashAlgorithmName, RSASignaturePadding padding)
                Type[] signatureTypes = { typeof(byte[]), s_hashAlgorithmNameType, s_rsaSignaturePaddingType };

                MethodInfo signDataMethod = typeof(RSA).GetMethod(
                    "SignData",
                    BindingFlags.Public | BindingFlags.Instance,
                    null,
                    signatureTypes,
                    null);

                var prop = s_rsaSignaturePaddingType.GetProperty("Pkcs1", BindingFlags.Static | BindingFlags.Public);
                var properties = s_rsaSignaturePaddingType.GetProperties(BindingFlags.Static | BindingFlags.Public);
                Type delegateType = typeof(Func<,,,,>).MakeGenericType(
                            typeof(RSA),
                            typeof(byte[]),
                            s_hashAlgorithmNameType,
                            s_rsaSignaturePaddingType,
                            typeof(byte[]));

                Delegate openDelegate = Delegate.CreateDelegate(delegateType, signDataMethod);
                s_rsaPkcs1SignMethod = (rsaArg, dataArg, algorithmArg) =>
                {
                    object[] args =
                    {
                        rsaArg,
                        dataArg,
                        Activator.CreateInstance(s_hashAlgorithmNameType, algorithmArg),
                        s_rsaSignaturePaddingType.GetProperty("Pkcs1", BindingFlags.Static | BindingFlags.Public).GetValue(null)
                    };

                    return (byte[])openDelegate.DynamicInvoke(args);
                };
            }

            return s_rsaPkcs1SignMethod(RSA, input, hashAlgorithmName);
        }

        internal bool Pkcs1VerifyData(byte[] input, byte[] signature, string hashAlgorithmName)
        {
            if (s_rsaPkcs1VerifyMethod == null)
            {
                // [X] VerifyData(byte[] data, byte[] signature, HashAlgorithmName hashAlgorithmName, RSASignaturePadding padding)
                // [ ] VerifyData(byte[] data, int offset, int count, byte[] signature, HashAlgorithmName hashAlgorithmName, RSASignaturePadding padding)
                // [ ] VerifyData(Stream data, byte[] signature, HashAlgorithmName hashAlgorithmName, RSASignaturePadding padding)
                Type[] signatureTypes = { typeof(byte[]), typeof(byte[]), s_hashAlgorithmNameType, s_rsaSignaturePaddingType };
                MethodInfo verifyDataMethod = typeof(RSA).GetMethod(
                    "VerifyData",
                    BindingFlags.Public | BindingFlags.Instance,
                    null,
                    signatureTypes,
                    null);

                Type delegateType = typeof(Func<,,,,,>).MakeGenericType(
                    typeof(RSA),
                    typeof(byte[]),
                    typeof(byte[]),
                    s_hashAlgorithmNameType,
                    s_rsaSignaturePaddingType,
                    typeof(bool));

                Delegate verifyDelegate = Delegate.CreateDelegate(delegateType, verifyDataMethod);
                s_rsaPkcs1VerifyMethod = (rsaArg, dataArg, signatureArg, algorithmArg) =>
                {
                    object[] args =
                    {
                        rsaArg,
                        dataArg,
                        signatureArg,
                        Activator.CreateInstance(s_hashAlgorithmNameType, algorithmArg),
                        s_rsaSignaturePaddingType.GetProperty("Pkcs1", BindingFlags.Static | BindingFlags.Public).GetValue(null)
                    };

                    return (bool)verifyDelegate.DynamicInvoke(args);
                };
            }

            return s_rsaPkcs1VerifyMethod(RSA, input, signature, hashAlgorithmName);
        }
    }
#endif
}
