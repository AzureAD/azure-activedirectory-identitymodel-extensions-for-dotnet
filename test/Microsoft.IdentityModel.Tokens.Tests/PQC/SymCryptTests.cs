// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Security.Cryptography;
using System.Text;
using Xunit;

namespace Microsoft.IdentityModel.Tokens.PQC.Tests
{
    /// <summary>
    /// This class tests integration with SymCrypt
    /// </summary>
    public class SymCryptTests
    {
        /// <summary>
        /// Compares that Dotnet HMAC and SymCrypt have the same signature
        /// </summary>
        [Fact]
        public void CompareHmacSymCryptDotNet()
        {
            byte[] data = Encoding.UTF8.GetBytes("Hello, SymCrypt!");
            try
            {
                int signatureLength = 32;
                byte[] symCryptHmacSignature = new byte[signatureLength];
                byte[] key = new byte[32];
                SYMCRYPT_HMAC_SHA256_EXPANDED_KEY expandedKey;
                SymCrypt.SymCryptHmacSha256ExpandKey(out expandedKey, key, key.Length);
                byte[] mldsaKey = SymCryptUtils.StructToByteArray(expandedKey);

                SymCrypt.SymCryptHmacSha256(
                    mldsaKey,
                    data,
                    data.Length,
                    symCryptHmacSignature);

                Aes aes = Aes.Create();
                aes.Key = key;
                HMACSHA256 hmac = new HMACSHA256(aes.Key);
                byte[] hmacSignature = hmac.ComputeHash(data);

                if (!SymCryptUtils.AreEqual(hmacSignature, symCryptHmacSignature))
                    Console.WriteLine("HMAC and SymCrypt DO NOT not have the same signature.");
                else
                    Console.WriteLine("HMAC and SymCrypt have the SAME signature.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
            }
        }

        [Fact]
        public void CompareShaSymCryptDotnet()
        {
            byte[] bytesToHash = Guid.NewGuid().ToByteArray();
            long cbHash = bytesToHash.Length;
            byte[] hashSymCrypt = new byte[32];
            SymCrypt.SymCryptSha256(bytesToHash, cbHash, hashSymCrypt);

            SHA256 sha256 = SHA256.Create();
            byte[] sha256Hash = sha256.ComputeHash(bytesToHash);

            if (!SymCryptUtils.AreEqual(sha256Hash, hashSymCrypt))
                Console.WriteLine("SHA256 and SymCrypt DO NOT not have the same signature.");
            else
                Console.WriteLine("SHA256 and SymCrypt have the SAME signature.");
        }

        [Fact]
        public void RsaSymCryptDotNet()
        {
            RsaSymCrypt rsaSymCrypt = new RsaSymCrypt(2048);
            byte[] bytesToSign = Guid.NewGuid().ToByteArray();
            byte[] signature = new byte[rsaSymCrypt.SignatureSize];
            rsaSymCrypt.SignData(bytesToSign, out signature);
        }
    }
}
