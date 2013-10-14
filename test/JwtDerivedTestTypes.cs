// ----------------------------------------------------------------------------------
//
// Copyright Microsoft Corporation
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
// ----------------------------------------------------------------------------------

using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Collections.Generic;
using System.IdentityModel.Configuration;
using System.IdentityModel.Protocols.WSTrust;
using System.IdentityModel.Selectors;
using System.IdentityModel.Tokens;
using System.Security.Claims;
using System.Security.Cryptography;

using IssuerNameRegistry = System.IdentityModel.Tokens.IssuerNameRegistry;

namespace System.IdentityModel.Test
{
    /// <summary>
    /// Returns the name passed in the constructor
    /// </summary>
    public class SetNameIssuerNameRegistry : IssuerNameRegistry
    {
        private string _issuer;
        public SetNameIssuerNameRegistry( string issuer )
        {
            _issuer = issuer;
        }

        public override string GetIssuerName( SecurityToken securityToken, string requestedIssuerName )
        {
            return _issuer;
        }

        public override string GetIssuerName( SecurityToken securityToken )
        {
            return _issuer;
        }
    }

    /// <summary>
    /// Used in extensibility tests to ensure that the same token flows through validation.
    /// </summary>
    public class DerivedJwtSecurityToken : JwtSecurityToken
    {
        public DerivedJwtSecurityToken( string encodedJwt )
            : base( encodedJwt ) 
        {
            Init();
        }

        public DerivedJwtSecurityToken( JwtHeader header, JwtPayload payload, string encodedJwt )
            : base( header, payload, encodedJwt ) 
        {
            Init();
        }

        public DerivedJwtSecurityToken(  string issuer = null, string audience = null, IEnumerable<Claim> claims = null, Lifetime lifetime = null, SigningCredentials signingCredentials = null )
            : base(  issuer, audience, claims, lifetime, signingCredentials )
        {
            Init();        
        }

        public bool ValidateAudienceCalled { get; set; }
        public bool ValidateLifetimeCalled { get; set; }
        public bool ValidateIssuerCalled { get; set; }
        public bool ValidateSignatureCalled { get; set; }
        public bool ValidateSigningTokenCalled { get; set; }
        public string Guid { get; set; }
        public static string Prefix = "DerivedJwtSecurityToken";

        private void Init()
        {
            ValidateAudienceCalled = false;
            ValidateLifetimeCalled = false;
            ValidateIssuerCalled = false;
            ValidateSignatureCalled = false;
            ValidateSigningTokenCalled = false;
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

        public override SecurityToken ReadToken( string jwtEncodedString )
        {
            if ( jwtEncodedString.StartsWith( DerivedJwtSecurityToken.Prefix ) )
            {

                return new DerivedJwtSecurityToken( jwtEncodedString.Substring( DerivedJwtSecurityToken.Prefix.Length ) );
            }
            
            return new JwtSecurityToken( jwtEncodedString );
        }

        public override Collections.ObjectModel.ReadOnlyCollection<ClaimsIdentity> ValidateToken( SecurityToken token )
        {
            return base.ValidateToken( token );
        }

        protected override void ValidateAudience( JwtSecurityToken jwt )
        {
            DerivedJwtSecurityToken derivedJwt = jwt as DerivedJwtSecurityToken;
            if ( derivedJwt != null )
            {
                derivedJwt.ValidateAudienceCalled = true;
            }
   
            Assert.IsFalse( jwt.GetType() != DerivedTokenType, "jwt.GetType() != DerivedTokenType, types:" + jwt.GetType() + ",  " + DerivedTokenType.ToString() );

            base.ValidateAudience( jwt );
        }

        protected override void ValidateAudience( JwtSecurityToken jwt, TokenValidationParameters validationParameters )
        {

            DerivedJwtSecurityToken derivedJwt = jwt as DerivedJwtSecurityToken;
            if ( derivedJwt != null )
            {
                derivedJwt.ValidateAudienceCalled = true;
            }

            Assert.IsFalse( jwt.GetType() != DerivedTokenType, "jwt.GetType() != DerivedTokenType, types:" + jwt.GetType() + ",  " + DerivedTokenType.ToString() );

            base.ValidateAudience( jwt, validationParameters );
        }

        protected override string ValidateIssuer( JwtSecurityToken jwt )
        {
            DerivedJwtSecurityToken derivedJwt = jwt as DerivedJwtSecurityToken;
            if ( derivedJwt != null )
            {
                derivedJwt.ValidateIssuerCalled = true;
            }

            Assert.IsFalse( jwt.GetType() != DerivedTokenType, "jwt.GetType() != DerivedTokenType, types:" + jwt.GetType() + ",  " + DerivedTokenType.ToString() );

            return base.ValidateIssuer( jwt );
        }

        protected override string ValidateIssuer( JwtSecurityToken jwt, TokenValidationParameters validationParameters )
        {
            DerivedJwtSecurityToken derivedJwt = jwt as DerivedJwtSecurityToken;
            if ( derivedJwt != null )
            {
                derivedJwt.ValidateIssuerCalled = true;
            }

            Assert.IsFalse( jwt.GetType() != DerivedTokenType , "jwt.GetType() != DerivedTokenType, types:" + jwt.GetType() + ",  " + DerivedTokenType.ToString() );

            return base.ValidateIssuer( jwt, validationParameters );
        }

        protected override void ValidateLifetime( JwtSecurityToken jwt )
        {
            DerivedJwtSecurityToken derivedJwt = jwt as DerivedJwtSecurityToken;
            if ( derivedJwt != null )
            {
                derivedJwt.ValidateLifetimeCalled = true;
            }

            Assert.IsFalse( jwt.GetType() != DerivedTokenType , "jwt.GetType() != DerivedTokenType, types:" + jwt.GetType() + ",  " + DerivedTokenType.ToString() );

            base.ValidateLifetime( jwt );
        }

        protected override void ValidateSignature( JwtSecurityToken jwt )
        {
            DerivedJwtSecurityToken derivedJwt = jwt as DerivedJwtSecurityToken;
            if ( derivedJwt != null )
            {
                derivedJwt.ValidateSignatureCalled = true;
            }

            Assert.IsFalse( jwt.GetType() != DerivedTokenType , "jwt.GetType() != DerivedTokenType, types:" + jwt.GetType() + ",  " + DerivedTokenType.ToString() );

            base.ValidateSignature( jwt );
        }

        protected override void ValidateSignature( JwtSecurityToken jwt, TokenValidationParameters validationParameters )
        {
            DerivedJwtSecurityToken derivedJwt = jwt as DerivedJwtSecurityToken;
            if ( derivedJwt != null )
            {
                derivedJwt.ValidateSignatureCalled = true;
            }

            Assert.IsFalse( jwt.GetType() != DerivedTokenType , "jwt.GetType() != DerivedTokenType, types:" + jwt.GetType() + ",  " + DerivedTokenType.ToString() );

            base.ValidateSignature( jwt, validationParameters );
        }

        protected override void ValidateSigningToken( JwtSecurityToken jwt )
        {
            DerivedJwtSecurityToken derivedJwt = jwt as DerivedJwtSecurityToken;
            if ( derivedJwt != null )
            {
                derivedJwt.ValidateSigningTokenCalled = true;
            }

            Assert.IsFalse( jwt.GetType() != DerivedTokenType , "jwt.GetType() != DerivedTokenType, types:" + jwt.GetType() + ",  " + DerivedTokenType.ToString() );

            base.ValidateSigningToken( jwt );
        }

        public override ClaimsPrincipal ValidateToken( JwtSecurityToken jwt )
        {
            return base.ValidateToken( jwt );
        }

        public override ClaimsPrincipal ValidateToken( JwtSecurityToken jwt, TokenValidationParameters validationParameters )
        {
            return base.ValidateToken( jwt, validationParameters );
        }

        public override ClaimsPrincipal ValidateToken( string jwtEncodedString )
        {
            return base.ValidateToken( jwtEncodedString );
        }

        public override ClaimsPrincipal ValidateToken( string jwtEncodedString, TokenValidationParameters validationParameters )
        {
            return base.ValidateToken( jwtEncodedString, validationParameters );
        }
    }

    public class CustomSecurityTokenServiceConfiguration : SecurityTokenServiceConfiguration
    {
        public CustomSecurityTokenServiceConfiguration()
            : base( "http://www.GotJwt.com" )
        {
            this.SecurityTokenService = typeof( CustomSecurityTokenService );

            JwtSecurityTokenHandler jwtHandler = new JwtSecurityTokenHandler();            
            this.SecurityTokenHandlers.Add(jwtHandler);

            this.DefaultTokenType = "urn:ietf:params:oauth:token-type:jwt";
        }
    }

    public class CustomSecurityTokenService : SecurityTokenService
    {
        public CustomSecurityTokenService()
            : base( new CustomSecurityTokenServiceConfiguration() )
        {
        }

        protected override ClaimsIdentity GetOutputClaimsIdentity( System.Security.Claims.ClaimsPrincipal principal, Protocols.WSTrust.RequestSecurityToken request, Scope scope )
        {
            return new ClaimsIdentity();
        }

        protected override Scope GetScope( ClaimsPrincipal principal, RequestSecurityToken request )
        {
            Scope scope = new Scope("http://www.relyingParty.com", KeyingMaterial.X509SigningCreds_2048_RsaSha2_Sha2 );
            scope.TokenEncryptionRequired = false;
            scope.SymmetricKeyEncryptionRequired = false;
            return scope;
        }
    }

    public class NotAsymmetricOrSymmetricSecurityKey : SecurityKey
    {
        public override byte[] DecryptKey( string algorithm, byte[] keyData )
        {
            throw new NotImplementedException();
        }

        public override byte[] EncryptKey( string algorithm, byte[] keyData )
        {
            throw new NotImplementedException();
        }

        public override bool IsAsymmetricAlgorithm( string algorithm )
        {
            throw new NotImplementedException();
        }

        public override bool IsSupportedAlgorithm( string algorithm )
        {
            throw new NotImplementedException();
        }

        public override bool IsSymmetricAlgorithm( string algorithm )
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

        public override byte[] GenerateDerivedKey( string algorithm, byte[] label, byte[] nonce, int derivedKeyLength, int offset )
        {
            throw new NotImplementedException();
        }

        public override System.Security.Cryptography.ICryptoTransform GetDecryptionTransform( string algorithm, byte[] iv )
        {
            throw new NotImplementedException();
        }

        public override System.Security.Cryptography.ICryptoTransform GetEncryptionTransform( string algorithm, byte[] iv )
        {
            throw new NotImplementedException();
        }

        public override int GetIVSize( string algorithm )
        {
            throw new NotImplementedException();
        }

        public override System.Security.Cryptography.KeyedHashAlgorithm GetKeyedHashAlgorithm( string algorithm )
        {
            return KeyedHashAlgorithm;
        }

        public override System.Security.Cryptography.SymmetricAlgorithm GetSymmetricAlgorithm( string algorithm )
        {
            throw new NotImplementedException();
        }

        public override byte[] GetSymmetricKey()
        {
            if ( SymmetricSecurityKey == null )
            {
                return null;
            }

            return SymmetricSecurityKey.GetSymmetricKey();
        }

        public override byte[] DecryptKey( string algorithm, byte[] keyData )
        {
            throw new NotImplementedException();
        }

        public override byte[] EncryptKey( string algorithm, byte[] keyData )
        {
            throw new NotImplementedException();
        }

        public override bool IsAsymmetricAlgorithm( string algorithm )
        {
            return false;
        }

        public override bool IsSupportedAlgorithm( string algorithm )
        {
           return true;
        }

        public override bool IsSymmetricAlgorithm( string algorithm )
        {
            return true;
        }

        public override int KeySize
        {
            get
            {
                if ( SymmetricSecurityKey != null )
                {
                    return SymmetricSecurityKey.KeySize;
                }

                return 256;
            }
        }
    }

    public class ReturnNullAsymmetricSecurityKey : AsymmetricSecurityKey
    {
        public ReturnNullAsymmetricSecurityKey( ) {}

        public AsymmetricSignatureDeformatter AsymmetricSignatureDeformatter { get; set; }
        public AsymmetricSignatureFormatter AsymmetricSignatureFormatter { get; set; }
        public HashAlgorithm HashAlgorithm { get; set; }

        public override System.Security.Cryptography.AsymmetricAlgorithm GetAsymmetricAlgorithm( string algorithm, bool privateKey )
        {
            throw new NotImplementedException();
        }

        public override System.Security.Cryptography.HashAlgorithm GetHashAlgorithmForSignature( string algorithm )
        {
            return HashAlgorithm;
        }

        public override System.Security.Cryptography.AsymmetricSignatureDeformatter GetSignatureDeformatter( string algorithm )
        {
            return AsymmetricSignatureDeformatter;
        }

        public override System.Security.Cryptography.AsymmetricSignatureFormatter GetSignatureFormatter( string algorithm )
        {
            return AsymmetricSignatureFormatter;
        }

        public override bool HasPrivateKey()
        {
            throw new NotImplementedException();
        }

        public override byte[] DecryptKey( string algorithm, byte[] keyData )
        {
            throw new NotImplementedException();
        }

        public override byte[] EncryptKey( string algorithm, byte[] keyData )
        {
            throw new NotImplementedException();
        }

        public override bool IsAsymmetricAlgorithm( string algorithm )
        {
            throw new NotImplementedException();
        }

        public override bool IsSupportedAlgorithm( string algorithm )
        {
            throw new NotImplementedException();
        }

        public override bool IsSymmetricAlgorithm( string algorithm )
        {
            throw new NotImplementedException();
        }

        public override int KeySize
        {
            get { throw new NotImplementedException(); }
        }
    }

    public class PublicJwtSecurityTokenHandler : JwtSecurityTokenHandler
    {
        public void ValidateAudiencePublic( JwtSecurityToken jwt )
        {
            base.ValidateAudience( jwt );
        }

        public void ValidateAudiencePublic( JwtSecurityToken jwt, TokenValidationParameters validationParameters )
        {
            base.ValidateAudience( jwt, validationParameters );
        }

        public string ValidateIssuerPublic( JwtSecurityToken jwt )
        {
            return base.ValidateIssuer( jwt );
        }

        public string ValidateIssuerPublic( JwtSecurityToken jwt, TokenValidationParameters validationParameters )
        {
            return base.ValidateIssuer( jwt, validationParameters );
        }

        public void ValidateLifetimePublic( JwtSecurityToken jwt )
        {
            base.ValidateLifetime( jwt );
        }

        public void ValidateSigningTokenPublic( JwtSecurityToken jwt )
        {
            base.ValidateSigningToken( jwt );
        }
    }

    /// <summary>
    /// Useful for trigging an exception.
    /// </summary>
    public class FaultingAsymmetricSecurityKey : AsymmetricSecurityKey
    {
        public FaultingAsymmetricSecurityKey( AsymmetricSecurityKey key = null, AsymmetricAlgorithm agorithm = null, AsymmetricSignatureDeformatter deformatter = null, AsymmetricSignatureFormatter formatter = null, HashAlgorithm hash = null, bool hasPrivateKey = false )
        {
            Key = key;
        }
        
        public AsymmetricSecurityKey Key { get; set; }
        public AsymmetricAlgorithm Algorithm { get; set; }
        public AsymmetricSignatureDeformatter deformatter { get; set; } 
        public AsymmetricSignatureFormatter formatter { get; set; }
        public HashAlgorithm hash { get; set; }
        public bool hasPrivateKey { get; set; }

        public override AsymmetricAlgorithm GetAsymmetricAlgorithm( string algorithm, bool privateKey )
        {
            return Key.GetAsymmetricAlgorithm( algorithm, privateKey );
        }

        public override HashAlgorithm GetHashAlgorithmForSignature( string algorithm )
        {
            return Key.GetHashAlgorithmForSignature( algorithm );
        }

        public override AsymmetricSignatureDeformatter GetSignatureDeformatter( string algorithm )
        {
            return Key.GetSignatureDeformatter( algorithm );
        }

        public override AsymmetricSignatureFormatter GetSignatureFormatter( string algorithm )
        {
            return Key.GetSignatureFormatter( algorithm );
        }

        public override bool HasPrivateKey()
        {
            return Key.HasPrivateKey();
        }

        public override int KeySize { get { return Key.KeySize; } }
        public override byte[] DecryptKey( string algorithm, byte[] keyData ) { return Key.DecryptKey( algorithm, keyData ); }
        public override byte[] EncryptKey( string algorithm, byte[] keyData ) { return Key.EncryptKey( algorithm, keyData ); }
        public override bool IsAsymmetricAlgorithm( string algorithm ) { return Key.IsAsymmetricAlgorithm( algorithm ); }
        public override bool IsSupportedAlgorithm( string algorithm ) { return Key.IsSupportedAlgorithm( algorithm ); }
        public override bool IsSymmetricAlgorithm( string algorithm ) { return Key.IsSymmetricAlgorithm( algorithm ); }
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

        public FaultingSymmetricSecurityKey( SymmetricSecurityKey key, Exception throwMe, SymmetricAlgorithm algorithm = null, KeyedHashAlgorithm keyedHash = null, byte[] keyBytes = null )
        {
            _throwMe = throwMe;
            _key = key;
            _keyedHash = keyedHash;
            _agorithm = algorithm;
            _keyBytes = keyBytes;
        }

        public override KeyedHashAlgorithm GetKeyedHashAlgorithm( string algorithm )
        {
            if ( _throwMe != null )
                throw _throwMe;

            return _keyedHash;
        }

        public override byte[] GetSymmetricKey()
        {
            if ( _throwMe != null )
                throw _throwMe;

            return _keyBytes; 
        }

        public override byte[] GenerateDerivedKey( string algorithm, byte[] label, byte[] nonce, int derivedKeyLength, int offset ) { return _key.GenerateDerivedKey( algorithm, label, nonce, derivedKeyLength, offset ); }
        public override ICryptoTransform GetDecryptionTransform( string algorithm, byte[] iv ) { return _key.GetDecryptionTransform( algorithm, iv ); }
        public override ICryptoTransform GetEncryptionTransform( string algorithm, byte[] iv ) { return _key.GetEncryptionTransform( algorithm, iv ); }
        public override int GetIVSize( string algorithm ) { return _key.GetIVSize( algorithm ); }
        public override SymmetricAlgorithm GetSymmetricAlgorithm( string algorithm ) { return _key.GetSymmetricAlgorithm( algorithm ); }


        public override int KeySize { get { return _key.KeySize; } }
        public override byte[] DecryptKey( string algorithm, byte[] keyData ) { return _key.DecryptKey( algorithm, keyData ); }
        public override byte[] EncryptKey( string algorithm, byte[] keyData ) { return _key.EncryptKey( algorithm, keyData ); }
        public override bool IsAsymmetricAlgorithm( string algorithm ) { return _key.IsAsymmetricAlgorithm( algorithm ); }
        public override bool IsSupportedAlgorithm( string algorithm ) { return _key.IsSupportedAlgorithm( algorithm ); }
        public override bool IsSymmetricAlgorithm( string algorithm ) { return _key.IsSymmetricAlgorithm( algorithm ); }
    }

    public class FaultingKeyedHashAlgorithm : KeyedHashAlgorithm
    {
        KeyedHashAlgorithm _keyedHashAlgorithm;
        Exception _throwMe;
        byte[] _key;

        public FaultingKeyedHashAlgorithm( KeyedHashAlgorithm keyedHashAlgorithm, Exception throwMe, byte[] key )
        {
            _keyedHashAlgorithm = keyedHashAlgorithm;
            _throwMe = throwMe;
            _key = key;
        }

        public override byte[] Key
        {
            get
            {
                if ( _throwMe != null )
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

        protected override void HashCore( byte[] array, int ibStart, int cbSize )
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
        public override void Validate( System.Security.Cryptography.X509Certificates.X509Certificate2 certificate )
        {
            return;
        }

        public static AlwaysSucceedCertificateValidator New { get { return new AlwaysSucceedCertificateValidator(); } }
    }

    public class AlwaysThrowCertificateValidator : X509CertificateValidator
    {
        public override void Validate( System.Security.Cryptography.X509Certificates.X509Certificate2 certificate )
        {
            throw new SecurityTokenValidationException( "Certificate not valid" );
        }
    }

    /// <summary>
    /// This allows a return value of a specific key or token
    /// Helpful for extensibility tests where the Jwt SKI is null or empty.
    /// </summary>
    public class SetReturnSecurityTokenResolver : SecurityTokenResolver
    {
        public SetReturnSecurityTokenResolver( SecurityToken token, SecurityKey key )
        {
            SecurityKey = key;
            SecurityToken = token;
        }

        public SecurityKey SecurityKey { get; set; }
        public SecurityToken SecurityToken { get; set; }

        protected override bool TryResolveSecurityKeyCore( SecurityKeyIdentifierClause keyIdentifierClause, out SecurityKey key )
        {
            key = SecurityKey;
            return true;
        }

        protected override bool TryResolveTokenCore( SecurityKeyIdentifierClause keyIdentifierClause, out SecurityToken token )
        {
            token = SecurityToken;
            return true;
        }

        protected override bool TryResolveTokenCore( SecurityKeyIdentifier keyIdentifier, out SecurityToken token )
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
        public override SignatureProvider CreateForSigning( SecurityKey key, string algorithm )
        {
            return null;
        }

        public override SignatureProvider CreateForVerifying( SecurityKey key, string algorithm )
        {
            return null;
        }
    }
}
