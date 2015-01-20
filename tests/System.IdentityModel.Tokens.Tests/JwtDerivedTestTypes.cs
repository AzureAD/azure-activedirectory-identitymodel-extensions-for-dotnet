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

using System.Collections.Generic;
using System.IdentityModel.Tokens;
using System.Security.Claims;
using System.Security.Cryptography;
using Xunit;

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
            Assert.NotNull(derivedJwt);
            ValidateAudienceCalled = true;
            base.ValidateAudience(audiences, jwt, validationParameters);
        }

        protected override string ValidateIssuer(string issuer, SecurityToken jwt, TokenValidationParameters validationParameters)
        {
            DerivedJwtSecurityToken derivedJwt = jwt as DerivedJwtSecurityToken;
            Assert.NotNull(derivedJwt);
            ValidateIssuerCalled = true;
            return base.ValidateIssuer(issuer, jwt, validationParameters);
        }

        protected override void ValidateIssuerSecurityKey(SecurityKey securityKey, SecurityToken securityToken, TokenValidationParameters validationParameters)
        {
            DerivedJwtSecurityToken derivedJwt = securityToken as DerivedJwtSecurityToken;
            Assert.NotNull(derivedJwt);
            ValidateIssuerSigningKeyCalled = true;
            base.ValidateIssuerSecurityKey(securityKey, securityToken, validationParameters);
        }

        protected override void ValidateLifetime(DateTime? notBefore, DateTime? expires, SecurityToken jwt, TokenValidationParameters validationParameters)
        {
            DerivedJwtSecurityToken derivedJwt = jwt as DerivedJwtSecurityToken;
            Assert.NotNull(derivedJwt);
            ValidateLifetimeCalled = true;
            base.ValidateLifetime(notBefore, expires, jwt, validationParameters);
        }

        protected override JwtSecurityToken ValidateSignature(string securityToken, TokenValidationParameters validationParameters)
        {
            Jwt = base.ValidateSignature(securityToken, validationParameters);
            DerivedJwtSecurityToken derivedJwt = Jwt as DerivedJwtSecurityToken;
            Assert.NotNull(derivedJwt);
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
        public override SignatureProvider GetSignatureProvider(string algorithm, bool verifyOnly)
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

        public override SignatureProvider GetSignatureProvider(string algorithm, bool verifyOnly)
        {
            throw new NotImplementedException();
        }

        public override int KeySize
        {
            get { throw new NotImplementedException(); }
        }

        public override bool HasPublicKey
        {
            get
            {
                throw new NotImplementedException();
            }
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

        public override bool HasPublicKey
        {
            get
            {
                throw new NotImplementedException();
            }
        }

        public override int KeySize { get { return _key.KeySize; } }

        public override SignatureProvider GetSignatureProvider(string algorithm, bool verifyOnly)
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
