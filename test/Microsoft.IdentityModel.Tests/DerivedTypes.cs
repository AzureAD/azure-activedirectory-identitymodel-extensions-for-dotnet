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

// This file contains derived types that are useful across multiple handlers / protocols.


using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;

namespace Microsoft.IdentityModel.Tests
{
#if LATER
    // waiting for xunit to be in net451, dotnet54
    public class DerivedClaim : Claim
    {
        string _dataString;
        byte[] _dataBytes;

        public DerivedClaim(Claim claim, string dataString, byte[] dataBytes)
            : base(claim)
        {
            _dataString = dataString;
            _dataBytes = dataBytes.CloneByteArray();
        }

        public DerivedClaim(DerivedClaim other)
            : this(other, (ClaimsIdentity)null)
        { }

        public DerivedClaim(DerivedClaim other, ClaimsIdentity subject)
            : base(other, subject)
        {
            _dataString = other._dataString;
            if (other._dataBytes != null)
                _dataBytes = other._dataBytes.CloneByteArray();
        }

        public DerivedClaim(BinaryReader reader)
            : this(reader, (ClaimsIdentity)null)
        { }

        public DerivedClaim(BinaryReader reader, ClaimsIdentity subject)
            : base(reader, subject)
        {
            _dataString = reader.ReadString();
            Int32 cb = reader.ReadInt32();
            if (cb > 0)
                _dataBytes = reader.ReadBytes(cb);
        }

        public byte[] DataBytes
        {
            get
            {
                return _dataBytes;
            }

            set
            {
                _dataBytes = value;
            }
        }

        public string DataString
        {
            get
            {
                return _dataString;
            }

            set
            {
                _dataString = value;
            }
        }

        public override Claim Clone()
        {
            return Clone((ClaimsIdentity)null);
        }

        public override Claim Clone(ClaimsIdentity identity)
        {
            return new DerivedClaim(this, identity);
        }

        public override void WriteTo(IO.BinaryWriter writer)
        {
            base.WriteTo(writer);
            writer.Write(_dataString);
            if (_dataBytes == null || _dataBytes.Length == 0)
            {
                writer.Write((Int32)0);
            }
            else
            {
                writer.Write((Int32)_dataBytes.Length);
                writer.Write(_dataBytes);
            }
        }
    }

    public class DerivedClaimsIdentity : ClaimsIdentity
    {
        string _dataString;
        byte[] _dataBytes;

        public DerivedClaimsIdentity(BinaryReader reader)
            : base(reader)
        {
            _dataString = reader.ReadString();
            Int32 cb = reader.ReadInt32();
            if (cb > 0)
                _dataBytes = reader.ReadBytes(cb);

        }

        public DerivedClaimsIdentity(IEnumerable<Claim> claims, string dataString, byte[] dataBytes)
            : base(claims)
        {
            _dataString = dataString;

            if (dataBytes != null && dataBytes.Length > 0)
                _dataBytes = dataBytes.CloneByteArray();
        }

        public string ClaimType { get; set; }

        public byte[] DataBytes
        {
            get
            {
                return _dataBytes;
            }

            set
            {
                _dataBytes = value;
            }
        }

        public string DataString
        {
            get
            {
                return _dataString;
            }

            set
            {
                _dataString = value;
            }
        }

        public override void WriteTo(BinaryWriter writer)
        {
            base.WriteTo(writer);
            writer.Write(_dataString);
            if (_dataBytes == null || _dataBytes.Length == 0)
            {
                writer.Write((Int32)0);
            }
            else
            {
                writer.Write((Int32)_dataBytes.Length);
                writer.Write(_dataBytes);
            }

            writer.Flush();
        }

        protected override Claim CreateClaim(BinaryReader reader)
        {
            return new DerivedClaim(reader, this);
        }
    }

    public class DerivedClaimsPrincipal : ClaimsPrincipal
    {
    }
#else
    public class CustomSecurityToken : SecurityToken
    {
        public override string Id { get { return "CustomSecurityToken"; } }

        public override string Issuer { get { return "CustomSecurityToken.Issuer"; } }

        public override SecurityKey SecurityKey { get { return null; } }

        public override SecurityKey SigningKey { get; set; }

        public override DateTime ValidFrom { get { return DateTime.UtcNow; } }

        public override DateTime ValidTo { get { return DateTime.UtcNow + TimeSpan.FromDays(1); } }
    }

    public class DerivedClaim : Claim
    {
        public DerivedClaim(Claim claim, string data, byte[] bytes)
            : base(claim.Value, claim.Type)
        {
        }
    }

    public class DerivedClaimsIdentity : ClaimsIdentity
    {
        public DerivedClaimsIdentity(IEnumerable<Claim> claims, string data, byte[] bytes)
            : base(claims)
        {

        }
    }

    public class DerivedClaimsPrincipal : ClaimsPrincipal
    {

    }
#endif

    /// <summary>
    /// Helpful for extensibility testing for errors.
    /// </summary>
    public class DerivedCryptoProviderFactory : CryptoProviderFactory
    {
        public SymmetricSignatureProvider SymmetricSignatureProviderForSigning { get; set; }

        public SymmetricSignatureProvider SymmetricSignatureProviderForVerifying { get; set; }

        public override SignatureProvider CreateForSigning(SecurityKey key, string algorithm)
        {
            return SymmetricSignatureProviderForSigning;
        }

        public override SignatureProvider CreateForVerifying(SecurityKey key, string algorithm)
        {
            return SymmetricSignatureProviderForVerifying;
        }
    }

    public class DerivedAuthenticatedEncryptionProvider : AuthenticatedEncryptionProvider
    {
        public DerivedAuthenticatedEncryptionProvider()
            : base(Default.SymmetricEncryptionKey256, SecurityAlgorithms.Aes128CbcHmacSha256)
        {
        }
        public DerivedAuthenticatedEncryptionProvider(SymmetricSecurityKey key, string algorithm)
            : base(key, algorithm)
        {
        }

        public bool DecryptCalled { get; set; } = false;

        public bool EncryptCalled { get; set; } = false;

        public bool GetKeyBytesCalled { get; set; } = false;

        public bool IsSupportedAlgorithmCalled { get; set; } = false;

        public bool ValidateKeySizeCalled { get; set; } = false;

        public override byte[] Decrypt(byte[] ciphertext, byte[] authenticatedData, byte[] iv, byte[] authenticationTag)
        {
            DecryptCalled = true;
            return base.Decrypt(ciphertext, authenticatedData, iv, authenticationTag);
        }

        public override AuthenticatedEncryptionResult Encrypt(byte[] plaintext, byte[] authenticatedData)
        {
            EncryptCalled = true;
            return base.Encrypt(plaintext, authenticatedData);
        }

        protected override byte[] GetKeyBytes(SecurityKey key)
        {
            GetKeyBytesCalled = true;
            return base.GetKeyBytes(key);
        }

        public byte[] GetKeyBytesPublic(SecurityKey key)
        {
            GetKeyBytesCalled = true;
            return base.GetKeyBytes(key);
        }

        protected override bool IsSupportedAlgorithm(SecurityKey key, string algorithm)
        {
            IsSupportedAlgorithmCalled = true;
            return base.IsSupportedAlgorithm(key, algorithm);
        }

        public bool IsSupportedAlgorithmPublic(SecurityKey key, string algorithm)
        {
            IsSupportedAlgorithmCalled = true;
            return base.IsSupportedAlgorithm(key, algorithm);
        }

        protected override void ValidateKeySize(SecurityKey key, string algorithm)
        {
            ValidateKeySizeCalled = true;
            base.ValidateKeySize(key, algorithm);
        }

        public void ValidateKeySizePublic(SecurityKey key, string algorithm)
        {
            ValidateKeySizeCalled = true;

            base.ValidateKeySize(key, algorithm);
        }
    }

    public class DerivedKeyWrapProvider : SymmetricKeyWrapProvider
    {
        public DerivedKeyWrapProvider(SecurityKey key, string algorithm)
            : base(key, algorithm)
        {
        }

        public bool GetSymmetricAlgorithmCalled { get; set; } = false;
        public bool IsSupportedAlgorithmCalled { get; set; } = false;
        public bool UnwrapKeyCalled { get; set; } = false;
        public bool WrapKeyCalled { get; set; } = false;
        protected override SymmetricAlgorithm GetSymmetricAlgorithm(SecurityKey key, string algorithm)
        {
            GetSymmetricAlgorithmCalled = true;
            return base.GetSymmetricAlgorithm(key, algorithm);
        }

        protected override bool IsSupportedAlgorithm(SecurityKey key, string algorithm)
        {
            IsSupportedAlgorithmCalled = true;
            return base.IsSupportedAlgorithm(key, algorithm);
        }

        public override byte[] UnwrapKey(byte[] keyBytes)
        {
            UnwrapKeyCalled = true;
            return base.UnwrapKey(keyBytes);
        }

        public override byte[] WrapKey(byte[] keyBytes)
        {
            WrapKeyCalled = true;
            return base.WrapKey(keyBytes);
        }
    }

    public class DerivedRsaKeyWrapProvider : RsaKeyWrapProvider
    {
        public DerivedRsaKeyWrapProvider(SecurityKey key, string algorithm, bool willUnwrap)
            : base(key, algorithm, willUnwrap)
        {
        }

        public bool IsSupportedAlgorithmCalled { get; set; } = false;
        public bool ResolveRsaAlgorithmCalled { get; set; } = false;
        public bool UnwrapKeyCalled { get; set; } = false;
        public bool WrapKeyCalled { get; set; } = false;

        protected override bool IsSupportedAlgorithm(SecurityKey key, string algorithm)
        {
            IsSupportedAlgorithmCalled = true;
            return base.IsSupportedAlgorithm(key, algorithm);
        }

        public override byte[] UnwrapKey(byte[] keyBytes)
        {
            UnwrapKeyCalled = true;
            return base.UnwrapKey(keyBytes);
        }

        public override byte[] WrapKey(byte[] keyBytes)
        {
            WrapKeyCalled = true;
            return base.WrapKey(keyBytes);
        }
    }

    /// <summary>
    /// Useful for trigging an exception.
    /// </summary>
    public class DerivedAsymmetricSecurityKey : AsymmetricSecurityKey
    {
        AsymmetricSecurityKey _key;

        public DerivedAsymmetricSecurityKey(AsymmetricSecurityKey key = null, AsymmetricAlgorithm agorithm = null, bool hasPrivateKey = false)
        {
            _key = key;
        }

        [System.Obsolete("HasPrivateKey method is deprecated, please use FoundPrivateKey instead.")]
        public override bool HasPrivateKey
        {
            get { return _key.HasPrivateKey; }
        }

        public override PrivateKeyStatus PrivateKeyStatus
        {
            get
            {
                return _key.PrivateKeyStatus;
            }
        }

        public override int KeySize { get { return _key.KeySize; } }
    }

    public class FaultingKeyedHashAlgorithm : KeyedHashAlgorithm
    {
        KeyedHashAlgorithm _keyedHashAlgorithm;
        Exception _throwMe;
        byte[] _key;

        public FaultingKeyedHashAlgorithm(KeyedHashAlgorithm keyedHashAlgorithm, Exception throwMe, byte[] key)
        {
            _keyedHashAlgorithm = keyedHashAlgorithm;
            _throwMe = throwMe;
            _key = key;
        }

        public override byte[] Key
        {
            get
            {
                if (_throwMe != null)
                {
                    throw _throwMe;
                }

                return _key;
            }

            set
            {
                _key = value;
            }
        }

        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            throw new NotImplementedException();
        }

        protected override byte[] HashFinal()
        {
            throw new NotImplementedException();
        }

        public override void Initialize()
        {
            throw new NotImplementedException();
        }
    }

    /// <summary>
    /// This works that is a parameter is null, we throw the exception when asked for the property
    /// </summary>
    public class FaultingSymmetricSecurityKey : SymmetricSecurityKey
    {
        Exception _throwMe;
        KeyedHashAlgorithm _keyedHash;
        SymmetricSecurityKey _key;
        SymmetricAlgorithm _agorithm;
        byte[] _keyBytes;

        public FaultingSymmetricSecurityKey(SymmetricSecurityKey key, Exception throwMe, SymmetricAlgorithm algorithm = null, KeyedHashAlgorithm keyedHash = null, byte[] keyBytes = null)
            : base(keyBytes)
        {
            _throwMe = throwMe;
            _key = key;
            _keyedHash = keyedHash;
            _agorithm = algorithm;
            _keyBytes = keyBytes;
        }

        public override byte[] Key
        {
            get
            {
                if (_throwMe != null)
                    throw _throwMe;

                return _keyBytes;
            }
        }

        public override int KeySize { get { return _key.KeySize; } }
    }

    public class NotAsymmetricOrSymmetricSecurityKey : SecurityKey
    {
        public override int KeySize
        {
            get { throw new NotImplementedException(); }
        }

        public static SecurityKey New { get { return new NotAsymmetricOrSymmetricSecurityKey(); } }
    }

    public class CustomCryptoProviderSecurityKey : SecurityKey
    {
        public CustomCryptoProviderSecurityKey(CustomCryptoProviderFactory  customCryptoProviderFactory)
        {
            CryptoProviderFactory = customCryptoProviderFactory;
        }

        public override int KeySize => throw new NotImplementedException();
    }

    public class ReturnNullAsymmetricSecurityKey : AsymmetricSecurityKey
    {
        public ReturnNullAsymmetricSecurityKey() { }

        [System.Obsolete("HasPrivateKey method is deprecated, please use FoundPrivateKey instead.")]
        public override bool HasPrivateKey
        {
            get { throw new NotImplementedException(); }
        }

        public override PrivateKeyStatus PrivateKeyStatus
        {
            get { throw new NotImplementedException(); }
        }

        public override int KeySize
        {
            get { throw new NotImplementedException(); }
        }
    }

    public class ReturnNullSymmetricSecurityKey : SymmetricSecurityKey
    {
        public ReturnNullSymmetricSecurityKey(byte[] keyBytes)
            : base(keyBytes)
        { }

        public SymmetricSecurityKey SymmetricSecurityKey { get; set; }

        public override byte[] Key
        {
            get
            {
                if (SymmetricSecurityKey == null)
                {
                    return null;
                }

                return SymmetricSecurityKey.Key;
            }
        }

        public override int KeySize
        {
            get
            {
                if (SymmetricSecurityKey != null)
                {
                    return SymmetricSecurityKey.KeySize;
                }

                return 256;
            }
        }
    }
}
