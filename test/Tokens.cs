//------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
//------------------------------------------------------------

using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IdentityModel.Protocols.WSTrust;
using System.IdentityModel.Selectors;
using System.IdentityModel.Tokens;
using System.Security.Claims;

namespace System.IdentityModel.Test
{
    public class CreateAndValidateParams
    {
        public JwtSecurityToken CompareTo { get; set; }
        public Type ExceptionType { get; set; }
        public SigningCredentials SigningCredentials { get; set; }
        public SecurityToken SigningToken { get; set; }
        public TokenValidationParameters TokenValidationParameters { get; set; }
        public IEnumerable<Claim> Claims { get; set; }
        public string Case { get; set; }
        public string Issuer { get; set; }
    }

    public static class JwtTestTokens
    {
        public static JwtSecurityToken Simple( string issuer, string originalIssuer )
        {
            return new JwtSecurityToken( issuer, "http://www.contoso.com", ClaimSets.Simple( issuer, originalIssuer ) );
        }

        public static JwtSecurityToken Create( string issuer, string originalIssuer, SigningCredentials signingCredentials )
        {
            JwtPayload payload = new JwtPayload( issuer, "urn:uri", ClaimSets.Simple( issuer, originalIssuer ), new Lifetime( DateTime.UtcNow, DateTime.UtcNow + TimeSpan.FromHours( 10 ) ));
            JwtHeader header = new JwtHeader( signingCredentials );
            return new JwtSecurityToken( header, payload, header.Encode() + "." + payload.Encode() + "." );
        }

        public static IEnumerable<CreateAndValidateParams> All
        {
            get
            {
                //yield return new CreateAndValidateParams
                //{
                //    Case = "ClaimSets.Simple",
                //    Claims = ClaimSets.Simple,
                //    CompareTo = Simple,
                //    ExceptionType = null,
                //    SigningCredentials = null,
                //    SigningToken = null,
                //    TokenValidationParameters = new TokenValidationParameters
                //                                {
                //                                     AudienceUriMode = AudienceUriMode.Never,
                //                                     ValidateIssuer = false,
                //                                     ValidateSignature = false,
                //                                     ValidateNotBefore = false,
                //                                     ValidateExpiration = false,
                //                                     SigningToken = null,
                //                                     SaveBootstrapContext = true,
                //                                 }
                //};

                string issuer = "issuer";
                string originalIssuer = "originalIssuer";

                yield return new CreateAndValidateParams
                {
                    Case = "ClaimSets.Simple_simpleSigned_Asymmetric",
                    Claims = ClaimSets.Simple( issuer, originalIssuer),
                    CompareTo = Create(issuer, originalIssuer, KeyingMaterial.X509SigningCreds_2048_RsaSha2_Sha2 ),
                    ExceptionType = null,
                    SigningCredentials = KeyingMaterial.X509SigningCreds_2048_RsaSha2_Sha2,
                    SigningToken = KeyingMaterial.X509Token_2048,
                    TokenValidationParameters = new TokenValidationParameters
                    {
                        AudienceUriMode = AudienceUriMode.Never,
                        SigningToken = KeyingMaterial.X509Token_2048,
                        ValidIssuer = issuer,
                    }
                };

                yield return new CreateAndValidateParams
                {
                    Case = "ClaimSets.Simple_simpleSigned_Symmetric",
                    Claims = ClaimSets.Simple( issuer, originalIssuer ),
                    CompareTo = Create( issuer, originalIssuer, KeyingMaterial.SymmetricSigningCreds_256_Sha2 ),
                    ExceptionType = null,
                    SigningCredentials = KeyingMaterial.SymmetricSigningCreds_256_Sha2,
                    SigningToken = KeyingMaterial.BinarySecretToken_256,
                    TokenValidationParameters = new TokenValidationParameters
                    {
                        AudienceUriMode = AudienceUriMode.Never,
                        SigningToken = KeyingMaterial.BinarySecretToken_256,
                        ValidIssuer = issuer,
                    }
                };
            }
        }

    }

    public class JWTWithKeys : JwtSecurityToken
    {
        static ReadOnlyCollection<SecurityKey> _keys = (new List<SecurityKey> { new InMemorySymmetricSecurityKey( KeyingMaterial.SymmetricKeyBytes_256 ) }).AsReadOnly();

        public JWTWithKeys( string jwtEncodedString )
            : base( jwtEncodedString )
        {
        }

        public JWTWithKeys( string issuer, string audience, IEnumerable<Claim> claims, DateTime validFrom, DateTime validTo )
            : base( issuer: issuer, audience: audience, claims: claims, signingCredentials: null, lifetime: new Lifetime( validFrom, validTo ) )
        {}

        public override ReadOnlyCollection<SecurityKey> SecurityKeys
        {
            get
            {
                return _keys;
            }
        }
    }

}