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

using Microsoft.IdentityModel.Test;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IdentityModel.Selectors;
using System.IdentityModel.Tokens;
using System.Security.Claims;
using System.Security.Cryptography;

namespace System.IdentityModel.Test
{
    /// <summary>
    /// Used in extensibility tests to ensure that the same token flows through validation.
    /// </summary>
    public class DerivedJwtSecurityToken : JwtSecurityToken
    {
        public DerivedJwtSecurityToken(string encodedJwt)
            : base(encodedJwt)
        {
            Init();
        }

        public DerivedJwtSecurityToken(string issuer = null, string audience = null, IEnumerable<Claim> claims = null, DateTime? expires = null, DateTime? notbefore = null, SigningCredentials signingCredentials = null)
            : base(issuer, audience, claims, expires, notbefore, signingCredentials)
        {
            Init();
        }

        public bool ValidateAudienceCalled { get; set; }
        public bool ValidateLifetimeCalled { get; set; }
        public bool ValidateIssuerCalled { get; set; }
        public bool ValidateSignatureCalled { get; set; }
        public bool ValidateSigningKeyCalled { get; set; }
        public string Guid { get; set; }

        private void Init()
        {
            ValidateAudienceCalled = false;
            ValidateLifetimeCalled = false;
            ValidateIssuerCalled = false;
            ValidateSignatureCalled = false;
            ValidateSigningKeyCalled = false;
        }
    }

    /// <summary>
    /// Ensures that all protected types use same token.
    /// </summary>
    public class DerivedJwtSecurityTokenHandler : JwtSecurityTokenHandler
    {
        public DerivedJwtSecurityTokenHandler()
            : base()
        {
        }

        public Type DerivedTokenType
        {
            get;
            set;
        }

        public bool ReadTokenCalled { get; set; }
        public bool ValidateAudienceCalled { get; set; }
        public bool ValidateLifetimeCalled { get; set; }
        public bool ValidateIssuerCalled { get; set; }
        public bool ValidateIssuerSigningKeyCalled { get; set; }
        public bool ValidateSignatureCalled { get; set; }

        public JwtSecurityToken Jwt { get; set; }

        public override SecurityToken ReadToken(string jwtEncodedString)
        {
            ReadTokenCalled = true;
            return new DerivedJwtSecurityToken(jwtEncodedString);
        }

        protected override void ValidateAudience(IEnumerable<string> audiences, SecurityToken jwt, TokenValidationParameters validationParameters)
        {
            DerivedJwtSecurityToken derivedJwt = jwt as DerivedJwtSecurityToken;
            Assert.IsNotNull(derivedJwt);
            ValidateAudienceCalled = true;
            base.ValidateAudience(audiences, jwt, validationParameters);
        }

        protected override string ValidateIssuer(string issuer, SecurityToken jwt, TokenValidationParameters validationParameters)
        {
            DerivedJwtSecurityToken derivedJwt = jwt as DerivedJwtSecurityToken;
            Assert.IsNotNull(derivedJwt);
            ValidateIssuerCalled = true;
            return base.ValidateIssuer(issuer, jwt, validationParameters);
        }

        protected override void ValidateIssuerSecurityKey(SecurityKey securityKey, SecurityToken securityToken, TokenValidationParameters validationParameters)
        {
            DerivedJwtSecurityToken derivedJwt = securityToken as DerivedJwtSecurityToken;
            Assert.IsNotNull(derivedJwt);
            ValidateIssuerSigningKeyCalled = true;
            base.ValidateIssuerSecurityKey(securityKey, securityToken, validationParameters);
        }

        protected override void ValidateLifetime(DateTime? notBefore, DateTime? expires, SecurityToken jwt, TokenValidationParameters validationParameters)
        {
            DerivedJwtSecurityToken derivedJwt = jwt as DerivedJwtSecurityToken;
            Assert.IsNotNull(derivedJwt);
            ValidateLifetimeCalled = true;
            base.ValidateLifetime(notBefore, expires, jwt, validationParameters);
        }

        protected override JwtSecurityToken ValidateSignature(string securityToken, TokenValidationParameters validationParameters)
        {
            Jwt = base.ValidateSignature(securityToken, validationParameters);
            DerivedJwtSecurityToken derivedJwt = Jwt as DerivedJwtSecurityToken;
            Assert.IsNotNull(derivedJwt);
            ValidateSignatureCalled = true;
            return Jwt;
        }

        public override ClaimsPrincipal ValidateToken(string securityToken, TokenValidationParameters validationParameters, out SecurityToken validatedToken)
        {
            return base.ValidateToken(securityToken, validationParameters, out validatedToken);
        }
    }

    public class PublicJwtSecurityTokenHandler : JwtSecurityTokenHandler
    {
        public void ValidateAudiencePublic(JwtSecurityToken jwt, TokenValidationParameters validationParameters)
        {
            base.ValidateAudience(new string[]{jwt.Issuer}, jwt, validationParameters);
        }

        public string ValidateIssuerPublic(JwtSecurityToken jwt, TokenValidationParameters validationParameters)
        {
            return base.ValidateIssuer(jwt.Issuer, jwt, validationParameters);
        }

        public void ValidateLifetimePublic(JwtSecurityToken jwt, TokenValidationParameters validationParameters)
        {
            base.ValidateLifetime(DateTime.UtcNow, DateTime.UtcNow, jwt, validationParameters);
        }

        public void ValidateSigningTokenPublic(SecurityKey securityKey, SecurityToken jwt, TokenValidationParameters validationParameters)
        {
            base.ValidateIssuerSecurityKey(securityKey, jwt, validationParameters);
        }
    }

    public class NotAsymmetricOrSymmetricSecurityKey : SecurityKey
    {
        public override byte[] DecryptKey(string algorithm, byte[] keyData)
        {
            throw new NotImplementedException();
        }

        public override byte[] EncryptKey(string algorithm, byte[] keyData)
        {
            throw new NotImplementedException();
        }

        public override bool IsAsymmetricAlgorithm(string algorithm)
        {
            throw new NotImplementedException();
        }

        public override bool IsSupportedAlgorithm(string algorithm)
        {
            throw new NotImplementedException();
        }

        public override bool IsSymmetricAlgorithm(string algorithm)
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
        public KeyedHashAlgorithm KeyedHashAlgorithm { get; set; }
        public SymmetricSecurityKey SymmetricSecurityKey { get; set; }

        public override byte[] GenerateDerivedKey(string algorithm, byte[] label, byte[] nonce, int derivedKeyLength, int offset)
        {
            throw new NotImplementedException();
        }

        public override System.Security.Cryptography.ICryptoTransform GetDecryptionTransform(string algorithm, byte[] iv)
        {
            throw new NotImplementedException();
        }

        public override System.Security.Cryptography.ICryptoTransform GetEncryptionTransform(string algorithm, byte[] iv)
        {
            throw new NotImplementedException();
        }

        public override int GetIVSize(string algorithm)
        {
            throw new NotImplementedException();
        }

        public override System.Security.Cryptography.KeyedHashAlgorithm GetKeyedHashAlgorithm(string algorithm)
        {
            return KeyedHashAlgorithm;
        }

        public override System.Security.Cryptography.SymmetricAlgorithm GetSymmetricAlgorithm(string algorithm)
        {
            throw new NotImplementedException();
        }

        public override byte[] GetSymmetricKey()
        {
            if (SymmetricSecurityKey == null)
            {
                return null;
            }

            return SymmetricSecurityKey.GetSymmetricKey();
        }

        public override byte[] DecryptKey(string algorithm, byte[] keyData)
        {
            throw new NotImplementedException();
        }

        public override byte[] EncryptKey(string algorithm, byte[] keyData)
        {
            throw new NotImplementedException();
        }

        public override bool IsAsymmetricAlgorithm(string algorithm)
        {
            return false;
        }

        public override bool IsSupportedAlgorithm(string algorithm)
        {
            return true;
        }

        public override bool IsSymmetricAlgorithm(string algorithm)
        {
            return true;
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

        public AsymmetricSignatureDeformatter AsymmetricSignatureDeformatter { get; set; }
        public AsymmetricSignatureFormatter AsymmetricSignatureFormatter { get; set; }
        public HashAlgorithm HashAlgorithm { get; set; }

        public override System.Security.Cryptography.AsymmetricAlgorithm GetAsymmetricAlgorithm(string algorithm, bool privateKey)
        {
            throw new NotImplementedException();
        }

        public override System.Security.Cryptography.HashAlgorithm GetHashAlgorithmForSignature(string algorithm)
        {
            return HashAlgorithm;
        }

        public override System.Security.Cryptography.AsymmetricSignatureDeformatter GetSignatureDeformatter(string algorithm)
        {
            return AsymmetricSignatureDeformatter;
        }

        public override System.Security.Cryptography.AsymmetricSignatureFormatter GetSignatureFormatter(string algorithm)
        {
            return AsymmetricSignatureFormatter;
        }

        public override bool HasPrivateKey()
        {
            throw new NotImplementedException();
        }

        public override byte[] DecryptKey(string algorithm, byte[] keyData)
        {
            throw new NotImplementedException();
        }

        public override byte[] EncryptKey(string algorithm, byte[] keyData)
        {
            throw new NotImplementedException();
        }

        public override bool IsAsymmetricAlgorithm(string algorithm)
        {
            throw new NotImplementedException();
        }

        public override bool IsSupportedAlgorithm(string algorithm)
        {
            throw new NotImplementedException();
        }

        public override bool IsSymmetricAlgorithm(string algorithm)
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
        public FaultingAsymmetricSecurityKey(AsymmetricSecurityKey key = null, AsymmetricAlgorithm agorithm = null, AsymmetricSignatureDeformatter deformatter = null, AsymmetricSignatureFormatter formatter = null, HashAlgorithm hash = null, bool hasPrivateKey = false)
        {
            Key = key;
        }

        public AsymmetricSecurityKey Key { get; set; }
        public AsymmetricAlgorithm Algorithm { get; set; }
        public AsymmetricSignatureDeformatter deformatter { get; set; }
        public AsymmetricSignatureFormatter formatter { get; set; }
        public HashAlgorithm hash { get; set; }
        public bool hasPrivateKey { get; set; }

        public override AsymmetricAlgorithm GetAsymmetricAlgorithm(string algorithm, bool privateKey)
        {
            return Key.GetAsymmetricAlgorithm(algorithm, privateKey);
        }

        public override HashAlgorithm GetHashAlgorithmForSignature(string algorithm)
        {
            return Key.GetHashAlgorithmForSignature(algorithm);
        }

        public override AsymmetricSignatureDeformatter GetSignatureDeformatter(string algorithm)
        {
            return Key.GetSignatureDeformatter(algorithm);
        }

        public override AsymmetricSignatureFormatter GetSignatureFormatter(string algorithm)
        {
            return Key.GetSignatureFormatter(algorithm);
        }

        public override bool HasPrivateKey()
        {
            return Key.HasPrivateKey();
        }

        public override int KeySize { get { return Key.KeySize; } }
        public override byte[] DecryptKey(string algorithm, byte[] keyData) { return Key.DecryptKey(algorithm, keyData); }
        public override byte[] EncryptKey(string algorithm, byte[] keyData) { return Key.EncryptKey(algorithm, keyData); }
        public override bool IsAsymmetricAlgorithm(string algorithm) { return Key.IsAsymmetricAlgorithm(algorithm); }
        public override bool IsSupportedAlgorithm(string algorithm) { return Key.IsSupportedAlgorithm(algorithm); }
        public override bool IsSymmetricAlgorithm(string algorithm) { return Key.IsSymmetricAlgorithm(algorithm); }
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
        {
            _throwMe = throwMe;
            _key = key;
            _keyedHash = keyedHash;
            _agorithm = algorithm;
            _keyBytes = keyBytes;
        }

        public override KeyedHashAlgorithm GetKeyedHashAlgorithm(string algorithm)
        {
            if (_throwMe != null)
                throw _throwMe;

            return _keyedHash;
        }

        public override byte[] GetSymmetricKey()
        {
            if (_throwMe != null)
                throw _throwMe;

            return _keyBytes;
        }

        public override byte[] GenerateDerivedKey(string algorithm, byte[] label, byte[] nonce, int derivedKeyLength, int offset) { return _key.GenerateDerivedKey(algorithm, label, nonce, derivedKeyLength, offset); }
        public override ICryptoTransform GetDecryptionTransform(string algorithm, byte[] iv) { return _key.GetDecryptionTransform(algorithm, iv); }
        public override ICryptoTransform GetEncryptionTransform(string algorithm, byte[] iv) { return _key.GetEncryptionTransform(algorithm, iv); }
        public override int GetIVSize(string algorithm) { return _key.GetIVSize(algorithm); }
        public override SymmetricAlgorithm GetSymmetricAlgorithm(string algorithm) { return _key.GetSymmetricAlgorithm(algorithm); }


        public override int KeySize { get { return _key.KeySize; } }
        public override byte[] DecryptKey(string algorithm, byte[] keyData) { return _key.DecryptKey(algorithm, keyData); }
        public override byte[] EncryptKey(string algorithm, byte[] keyData) { return _key.EncryptKey(algorithm, keyData); }
        public override bool IsAsymmetricAlgorithm(string algorithm) { return _key.IsAsymmetricAlgorithm(algorithm); }
        public override bool IsSupportedAlgorithm(string algorithm) { return _key.IsSupportedAlgorithm(algorithm); }
        public override bool IsSymmetricAlgorithm(string algorithm) { return _key.IsSymmetricAlgorithm(algorithm); }
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

    public class AlwaysSucceedCertificateValidator : X509CertificateValidator
    {
        public override void Validate(System.Security.Cryptography.X509Certificates.X509Certificate2 certificate)
        {
            return;
        }

        public static AlwaysSucceedCertificateValidator New { get { return new AlwaysSucceedCertificateValidator(); } }
    }

    public class AlwaysThrowCertificateValidator : X509CertificateValidator
    {
        public override void Validate(System.Security.Cryptography.X509Certificates.X509Certificate2 certificate)
        {
            throw new SecurityTokenValidationException("Certificate not valid");
        }
    }

    /// <summary>
    /// This allows a return value of a specific key or token
    /// Helpful for extensibility tests where the Jwt SKI is null or empty.
    /// </summary>
    public class SetReturnSecurityTokenResolver : SecurityTokenResolver
    {
        public SetReturnSecurityTokenResolver(SecurityToken token, SecurityKey key)
        {
            SecurityKey = key;
            SecurityToken = token;
        }

        public SecurityKey SecurityKey { get; set; }
        public SecurityToken SecurityToken { get; set; }

        protected override bool TryResolveSecurityKeyCore(SecurityKeyIdentifierClause keyIdentifierClause, out SecurityKey key)
        {
            key = SecurityKey;
            return true;
        }

        protected override bool TryResolveTokenCore(SecurityKeyIdentifierClause keyIdentifierClause, out SecurityToken token)
        {
            token = SecurityToken;
            return true;
        }

        protected override bool TryResolveTokenCore(SecurityKeyIdentifier keyIdentifier, out SecurityToken token)
        {
            token = SecurityToken;
            return true;
        }
    }

    /// <summary>
    /// Helpful for extensibility testing for errors.
    /// </summary>
    public class AlwaysReturnNullSignatureProviderFactory : SignatureProviderFactory
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
}
