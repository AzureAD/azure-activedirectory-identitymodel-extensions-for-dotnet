using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Microsoft.IdentityModel.Logging;

namespace Microsoft.IdentityModel.Tokens
{
    //public class AesKWDecryptionProvider : IDecryptionProvider
    //{
    //    private byte[] _key;
    //    private byte[] _iv;
    //    private string _algorithm;

    //    public byte[] Decrypt(byte[] ciphertext)
    //    {
    //        if (ciphertext == null)
    //            throw LogHelper.LogArgumentNullException("input");

    //        AesKw aeskw = null;
    //        if (_algorithm.Equals("A128KW", StringComparison.Ordinal))
    //        {
    //            aeskw = new AesKw128();
    //        }
    //        else if (_algorithm.Equals("A256KW", StringComparison.Ordinal))
    //        {
    //            aeskw = new AesKw256();
    //        }
    //        else
    //        {
    //            // TODO (Yan) Add a new log message for this and throw exception
    //        }

    //        if (aeskw != null)
    //            return aeskw.CreateDecryptor(_key, _iv).TransformFinalBlock(ciphertext, 0, ciphertext.Length);

    //        AesCbcHmacSha2 aesCbcHmacSha = null;
    //        if (_algorithm.Equals("A128CBC-HS256", StringComparison.Ordinal))
    //        {
    //            aesCbcHmacSha = new Aes128CbcHmacSha256();
    //        }
    //        else if (_algorithm.Equals("A256CBC-HS512", StringComparison.Ordinal))
    //        {
    //            aesCbcHmacSha = new Aes256CbcHmacSha512();
    //        }
    //        else
    //        {
    //            // TODO (Yan) Add a new log message for this and throw exception
    //        }

    //        if (aesCbcHmacSha != null)
    //            return 
    //    }
    //}
}
