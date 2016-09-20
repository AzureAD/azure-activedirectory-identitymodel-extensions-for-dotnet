//
// Copyright © Microsoft Corporation, All Rights Reserved
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// THIS CODE IS PROVIDED *AS IS* BASIS, WITHOUT WARRANTIES OR CONDITIONS
// OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING WITHOUT LIMITATION
// ANY IMPLIED WARRANTIES OR CONDITIONS OF TITLE, FITNESS FOR A
// PARTICULAR PURPOSE, MERCHANTABILITY OR NON-INFRINGEMENT.
//
// See the Apache License, Version 2.0 for the specific language
// governing permissions and limitations under the License.

using System;
using System.Globalization;
using System.Security.Cryptography;

namespace Microsoft.IdentityModel.Tokens
{
    public abstract class AesCbcHmacSha2 : SymmetricEncryptionAlgorithm
    {
        protected AesCbcHmacSha2( string name )
            : base( name )
        {
        }

        public override ICryptoTransform CreateDecryptor( byte[] key, byte[] iv, byte[] authenticationData )
        {
            if ( key == null )
                throw new CryptographicException( "No key material" );

            if ( iv == null )
                throw new CryptographicException( "No initialization vector" );

            if ( authenticationData == null )
                throw new CryptographicException( "No associated data" );

            // Create the Decryptor
            return new AesCbcHmacSha2Decryptor( Name, key, iv, authenticationData );
        }

        public override ICryptoTransform CreateEncryptor( byte[] key, byte[] iv, byte[] authenticationData )
        {
            if ( authenticationData == null )
                throw new CryptographicException( "No associated data" );

            // Create the Encryptor
            return new AesCbcHmacSha2Encryptor( Name, key, iv, authenticationData );
        }

        private static void GetAlgorithmParameters( string algorithm, byte[] key, out byte[] aes_key, out byte[] hmac_key, out HMAC hmac )
        {
            switch ( algorithm )
            {
                case Aes128CbcHmacSha256.AlgorithmName:
                    {
                        if ( ( key.Length << 3 ) < 256 )
                            throw new CryptographicException( string.Format( CultureInfo.CurrentCulture, "{0} key length in bits {1} < 256", algorithm, key.Length << 3 ) );

                        hmac_key = new byte[128 >> 3];
                        aes_key  = new byte[128 >> 3];
                        Array.Copy( key, hmac_key, 128 >> 3 );
                        Array.Copy( key, 128 >> 3, aes_key, 0, 128 >> 3 );

                        hmac = new HMACSHA256( hmac_key );

                        break;
                    }
                    
                case Aes256CbcHmacSha512.AlgorithmName:
                    {
                        if ( ( key.Length << 3 ) < 512 )
                            throw new CryptographicException(string.Format( CultureInfo.CurrentCulture, "{0} key length in bits {1} < 512", algorithm, key.Length << 3 ));

                        hmac_key = new byte[256 >> 3];
                        aes_key  = new byte[256 >> 3];
                        Array.Copy( key, hmac_key, 256 >> 3 );
                        Array.Copy( key, 256 >> 3, aes_key, 0, 256 >> 3 );

                        hmac = new HMACSHA512( hmac_key );

                        break;
                    }

                default:
                    {
                        throw new CryptographicException(string.Format( CultureInfo.CurrentCulture, "Unsupported algorithm: {0}", algorithm ));
                    }
            }
        }

        private static int GetKeySize(string algorithm)
        {
            switch (algorithm)
            {
                case Aes128CbcHmacSha256.AlgorithmName:
                    return 128;

                case Aes256CbcHmacSha512.AlgorithmName:
                    return 256;
                    
                default:
                    throw new CryptographicException(string.Format(CultureInfo.CurrentCulture, "Unsupported algorithm: {0}", algorithm));
            }
        }
        
        class AesCbcHmacSha2Encryptor : IAuthenticatedCryptoTransform
        {
            readonly byte[] _hmac_key;

            readonly byte[] _associated_data_length;

            //#if NETSTANDARD1_4
            //            AesManaged _aesManaged;
            //#else
            //            RijndaelManaged _aes;
            //#endif

            SymmetricAlgorithm _aes;
            HMAC _hmac;

            ICryptoTransform _inner;
            byte[] _tag;
            byte[] _iv;
            byte[] _key;

            internal AesCbcHmacSha2Encryptor( string name, byte[] key, byte[] iv, byte[] associatedData )
            {
                if (key != null)
                {
                    // Split the key to get the AES key, the HMAC key and the HMAC object
                    byte[] aesKey;

                    GetAlgorithmParameters(name, key, out aesKey, out _hmac_key, out _hmac);
                    // Create the AES provider with giving key
#if NETSTANDARD1_4
                    _aes = new AesManaged { Mode = CipherMode.CBC, Padding = PaddingMode.PKCS7, KeySize = aesKey.Length * 8, Key = aesKey };
#else
                    _aes = new RijndaelManaged { Mode = CipherMode.CBC, Padding = PaddingMode.PKCS7, KeySize = aesKey.Length * 8, Key = aesKey };
#endif
                    _key = key;
                }
                else
                {
                    // Create the AES provider with specific key size
                    int keySize = GetKeySize(name);
#if NETSTANDARD1_4
                    _aes = new AesManaged { Mode = CipherMode.CBC, Padding = PaddingMode.PKCS7, KeySize = keySize };
#else
                    _aes = new RijndaelManaged { Mode = CipherMode.CBC, Padding = PaddingMode.PKCS7, KeySize = keySize };
#endif
                    _hmac_key = _aes.Key;

                    if (name == Aes128CbcHmacSha256.AlgorithmName)
                    {
                        _hmac = new HMACSHA256(_hmac_key);
                    }
                    else if (name == Aes256CbcHmacSha512.AlgorithmName)
                    {
                        _hmac = new HMACSHA512(_hmac_key);
                    }
                    else
                    {
                        // TODO: Add unsupported exception
                        throw new CryptographicException(string.Format(CultureInfo.CurrentCulture, "Unsupported algorithm: {0}", name));
                    }

                    _key = new byte[keySize];
                    Array.Copy(_hmac_key, _key, keySize >> 3);
                    Array.Copy(_aes.Key, 0, _key, keySize >> 3, keySize >> 3);
                }

                if (iv != null)
                {
                    _aes.IV = iv;
                }
                _iv = _aes.IV;

                _inner = _aes.CreateEncryptor();

                _associated_data_length = ConvertToBigEndian( associatedData.Length * 8 );

                // Prime the hash.
                _hmac.TransformBlock( associatedData, 0, associatedData.Length, associatedData, 0 );
                _hmac.TransformBlock(_iv, 0, _iv.Length, _iv, 0 );
            }

            public byte[] Tag
            {
                get { return _tag; }
            }

            public byte[] IV
            {
                get { return _iv;  }
            }

            public byte[] Key
            {
                get { return _key; }
            }

            public bool CanReuseTransform
            {
	            get { return _inner.CanReuseTransform; }
            }

            public bool CanTransformMultipleBlocks
            {
	            get { return _inner.CanTransformMultipleBlocks; }
            }

            public int InputBlockSize
            {
	            get { return _inner.InputBlockSize; }
            }

            public int OutputBlockSize
            {
	            get { return _inner.OutputBlockSize; }
            }

            public int TransformBlock( byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset )
            {
                // Encrypt the block
                var result = _inner.TransformBlock( inputBuffer, inputOffset, inputCount, outputBuffer, outputOffset );

                // Add it to the running hash
                _hmac.TransformBlock( outputBuffer, outputOffset, result, outputBuffer, outputOffset );

                return result;
            }

            public byte[] TransformFinalBlock( byte[] inputBuffer, int inputOffset, int inputCount )
            {
                // Encrypt the block
                var result = _inner.TransformFinalBlock( inputBuffer, inputOffset, inputCount );

                // Add it to the running hash
                _hmac.TransformBlock( result, 0, result.Length, result, 0 );

                // Add the associated_data_length bytes to the hash
                _hmac.TransformFinalBlock( _associated_data_length, 0, _associated_data_length.Length );

                // Compute the tag
                _tag = new byte[_hmac_key.Length];
                Array.Copy( _hmac.Hash, _tag, _hmac_key.Length );

                return result;
            }

            public void Dispose()
            {
 	           Dispose( true );
               GC.SuppressFinalize( this );
            }

            protected virtual void Dispose( bool disposing )
            {
                if ( disposing )
                {
                    if ( _inner != null )
                    {
                        _inner.Dispose();
                        _inner = null;
                    }

                    if ( _hmac != null )
                    {
                        _hmac.Dispose();
                        _hmac = null;
                    }

                    if ( _aes != null )
                    {
                        _aes.Dispose();
                        _aes = null;
                    }
                }
            }
        }

        class AesCbcHmacSha2Decryptor : IAuthenticatedCryptoTransform
        {
            readonly byte[]  _hmac_key;

            readonly byte[]  _associated_data_length;

            //#if NETSTANDARD1_4
            //#else
            //            RijndaelManaged  _aes;
            //#endif
            SymmetricAlgorithm _aes;
            HMAC             _hmac;

            ICryptoTransform _inner;
            byte[] _tag;
            byte[] _iv;
            byte[] _key;

            internal AesCbcHmacSha2Decryptor( string name, byte[] key, byte[] iv, byte[] associatedData )
            {
                // Split the key to get the AES key, the HMAC key and the HMAC object
                byte[] aesKey;

                GetAlgorithmParameters( name, key, out aesKey, out _hmac_key, out _hmac );

#if NETSTANDARD1_4
                _aes = new AesManaged { Mode = CipherMode.CBC, Padding = PaddingMode.PKCS7, KeySize = aesKey.Length*8, Key = aesKey, IV = iv };
#else
                // Create the AES provider
                _aes = new RijndaelManaged { Mode = CipherMode.CBC, Padding = PaddingMode.PKCS7, KeySize = aesKey.Length*8, Key = aesKey, IV = iv };
#endif
                _inner = _aes.CreateDecryptor();

                _associated_data_length = ConvertToBigEndian( associatedData.Length * 8 );

                // Prime the hash.
                _hmac.TransformBlock( associatedData, 0, associatedData.Length, associatedData, 0 );
                _hmac.TransformBlock( iv, 0, iv.Length, iv, 0 );
            }

            public byte[] Tag
            {
                get { return _tag; }
            }
            public byte[] IV
            {
                get { return _iv; }
            }

            public byte[] Key
            {
                get { return _key; }
            }

            public bool CanReuseTransform
            {
	            get { return _inner.CanReuseTransform; }
            }

            public bool CanTransformMultipleBlocks
            {
	            get { return _inner.CanTransformMultipleBlocks; }
            }

            public int InputBlockSize
            {
	            get { return _inner.InputBlockSize; }
            }

            public int OutputBlockSize
            {
	            get { return _inner.OutputBlockSize; }
            }

            public int TransformBlock( byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset )
            {
                // Add the cipher text to the running hash
                _hmac.TransformBlock( inputBuffer, inputOffset, inputCount, inputBuffer, inputOffset );

                // Decrypt the cipher text
                return _inner.TransformBlock( inputBuffer, inputOffset, inputCount, outputBuffer, outputOffset );
            }

            public byte[] TransformFinalBlock( byte[] inputBuffer, int inputOffset, int inputCount )
            {
                // Add the cipher text to the running hash
                _hmac.TransformBlock( inputBuffer, inputOffset, inputCount, inputBuffer, inputOffset );

                // Add the associated_data_length bytes to the hash
                _hmac.TransformFinalBlock( _associated_data_length, 0, _associated_data_length.Length );

                // Compute the tag
                _tag = new byte[_hmac_key.Length];
                Array.Copy( _hmac.Hash, _tag, _hmac_key.Length );

                return _inner.TransformFinalBlock( inputBuffer, inputOffset, inputCount );
            }

            public void Dispose()
            {
                Dispose( true );
                GC.SuppressFinalize( this );
            }

            protected virtual void Dispose( bool disposing )
            {
                if ( disposing )
                {
                    if ( _inner != null )
                    {
                        _inner.Dispose();
                        _inner = null;
                    }

                    if ( _hmac != null )
                    {
                        _hmac.Dispose();
                        _hmac = null;
                    }

                    if ( _aes != null )
                    {
                        _aes.Dispose();
                        _aes = null;
                    }
                }
            }
        }

        static byte[] ConvertToBigEndian( Int64 i )
        {
            byte[] temp = BitConverter.GetBytes( i );

            if ( BitConverter.IsLittleEndian )
            {
                Array.Reverse( temp );
            }

            return temp;
        }
    }
}
