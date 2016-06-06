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

// This file contains derived types that are usefull across multiple handlers / protocols.


using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace Microsoft.IdentityModel.Tokens.Tests
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

    public class NotAsymmetricOrSymmetricSecurityKey : SecurityKey
    {
        public override bool IsSupportedAlgorithm(string algorithm)
        {
            throw new NotImplementedException();
        }

        public override int KeySize
        {
            get { throw new NotImplementedException(); }
        }

        public static SecurityKey New { get { return new NotAsymmetricOrSymmetricSecurityKey(); } }
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

    public class ReturnNullAsymmetricSecurityKey : AsymmetricSecurityKey
    {
        public ReturnNullAsymmetricSecurityKey() { }

        public override bool HasPrivateKey
        {
            get { throw new NotImplementedException(); }
        }

        public override bool IsSupportedAlgorithm(string algorithm)
        {
            throw new NotImplementedException();
        }

        public override int KeySize
        {
            get { throw new NotImplementedException(); }
        }
    }

    /// <summary>
    /// Useful for trigging an exception.
    /// </summary>
    public class FaultingAsymmetricSecurityKey : AsymmetricSecurityKey
    {
        AsymmetricSecurityKey _key;

        public FaultingAsymmetricSecurityKey(AsymmetricSecurityKey key = null, AsymmetricAlgorithm agorithm = null, bool hasPrivateKey = false)
        {
            _key = key;
        }

        public override bool HasPrivateKey
        {
            get { return _key.HasPrivateKey; }
        }

        public override int KeySize { get { return _key.KeySize; } }

        public override bool IsSupportedAlgorithm(string algorithm)
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
    /// Helpful for extensibility testing for errors.
    /// </summary>
    public class AlwaysReturnNullCryptoProviderFactory : CryptoProviderFactory
    {
        public override SignatureProvider CreateForSigning(SecurityKey key, string algorithm)
        {
            return null;
        }

        public override SignatureProvider CreateForVerifying(SecurityKey key, string algorithm)
        {
            return null;
        }
    }

    public class CustomSignatureProvider : SignatureProvider
    {
        public CustomSignatureProvider(SecurityKey key, string algorithm)
            : base(key, algorithm)
        { }

        public bool DisposeCalled { get; set; } = false;

        public bool SignCalled { get; set; } = false;

        public bool VerifyCalled { get; set; } = false;

        public override byte[] Sign(byte[] input)
        {
            SignCalled = true;
            return Encoding.UTF8.GetBytes("SignedBytes");
        }

        public override bool Verify(byte[] input, byte[] signature)
        {
            VerifyCalled = true;
            return true;
        }

        protected override void Dispose(bool disposing)
        {
            DisposeCalled = true;
        }
    }

    public class CustomCryptoProviderFactory : CryptoProviderFactory
    {
        public CustomCryptoProviderFactory()
        {
        }

        public SignatureProvider SignatureProvider { get; set; }

        public bool CreateForSigningCalled { get; set; } = false;

        public bool CreateForVerifyingCalled { get; set; } = false;

        public bool ReleaseSignatureProviderCalled { get; set; } = false;

        public override SignatureProvider CreateForSigning(SecurityKey key, string algorithm)
        {
            CreateForSigningCalled = true;
            return SignatureProvider;
        }

        public override SignatureProvider CreateForVerifying(SecurityKey key, string algorithm)
        {
            CreateForVerifyingCalled = true;
            return SignatureProvider;
        }

        public override void ReleaseSignatureProvider(SignatureProvider signatureProvider)
        {
            ReleaseSignatureProviderCalled = true;
            signatureProvider.Dispose();
        }
    }
}
