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

using System.IdentityModel.Tokens;
using System.IO;
using System.Text;
using System.Xml;
using Xunit;

namespace System.IdentityModel.Test
{
    /// <summary>
    /// This test is a good place to grook how to create tokens.
    /// </summary>
    public class PerformanceTests
    {
        [Fact(DisplayName = "Performance tests for creating Jwts" )]
        public void Jwt_Performance()
        {            
            SecurityTokenDescriptor tokenDescriptor;
            tokenDescriptor = new SecurityTokenDescriptor()
            {
                Lifetime = new Lifetime( DateTime.UtcNow, DateTime.UtcNow + TimeSpan.FromHours( 24 ) ),
                SigningCredentials = KeyingMaterial.AsymmetricSigningCreds_2048_RsaSha2_Sha2,
                Subject = Subjects.Simple( Issuers.GotJwt, Issuers.GotJwtOriginal ),
                TokenIssuerName = Issuers.GotJwt,
                AppliesToAddress = Audiences.AuthFactors,
            };

            Console.WriteLine( "\n====================\nAsymmetric" );
            Console.WriteLine( "\n====================\nValidate\n" );

            RunValidationTests( tokenDescriptor, KeyingMaterial.AsymmetricX509Token_2048, KeyingMaterial.AsymmetricKey_2048, 50, false );
            RunValidationTests( tokenDescriptor, KeyingMaterial.AsymmetricX509Token_2048, KeyingMaterial.AsymmetricKey_2048, 5000, true );

            Console.WriteLine( "\n====================\nCreate\n" );
            RunCreationTests( tokenDescriptor, 50, false );
            RunCreationTests( tokenDescriptor, 5000 );

            tokenDescriptor = new SecurityTokenDescriptor() 
            { 
                Lifetime = new Lifetime( DateTime.UtcNow, DateTime.UtcNow + TimeSpan.FromHours( 24 ) ),
                SigningCredentials = KeyingMaterial.SymmetricSigningCreds_256_Sha2,
                Subject = Subjects.Simple( Issuers.GotJwt, Issuers.GotJwtOriginal ),
                TokenIssuerName = Issuers.GotJwt,
                AppliesToAddress = Audiences.AuthFactors,
            };

            Console.WriteLine( "\n================\nSymmetric" );
            Console.WriteLine( "\n====================\nValidate\n" );
            RunValidationTests( tokenDescriptor, KeyingMaterial.BinarySecretToken_256, KeyingMaterial.SymmetricSecurityKey_256, 50, false );
            RunValidationTests( tokenDescriptor, KeyingMaterial.BinarySecretToken_256, KeyingMaterial.SymmetricSecurityKey_256, 10000, true );

            Console.WriteLine( "\n====================\nCreate\n" );
            RunCreationTests( tokenDescriptor, 100, false );
            RunCreationTests( tokenDescriptor, 10000 );
        }

        private void RunValidationTests( SecurityTokenDescriptor tokenDescriptor, SecurityToken securityToken, SecurityKey key, int iterations, bool display = true )
        {
            // Create jwts using wif
            // Create Saml2 tokens
            // Create Saml tokens

            DateTime started;
            string validating = "Validating, signed: '{0}', '{1}' Tokens. Time: '{2}'";

            SetReturnSecurityTokenResolver str = new Test.SetReturnSecurityTokenResolver( securityToken, key );
            
            SecurityTokenHandlerConfiguration tokenHandlerConfiguration = new SecurityTokenHandlerConfiguration()
            {
                IssuerTokenResolver = str,
                SaveBootstrapContext = true,
                CertificateValidator = AlwaysSucceedCertificateValidator.New,
                AudienceRestriction = new AudienceRestriction( AudienceUriMode.Never ),
                IssuerNameRegistry = new SetNameIssuerNameRegistry( Issuers.GotJwt ),
            };

            Saml2SecurityTokenHandler samlTokenHandler = new Saml2SecurityTokenHandler();
            Saml2SecurityToken token = samlTokenHandler.CreateToken( tokenDescriptor ) as Saml2SecurityToken;
            StringBuilder sb = new StringBuilder();
            XmlWriter writer = XmlWriter.Create(sb);
            samlTokenHandler.WriteToken( writer, token );                                    
            writer.Flush();
            writer.Close();
            string tokenXml = sb.ToString();

            samlTokenHandler.Configuration = tokenHandlerConfiguration;
            started = DateTime.UtcNow;
            for ( int i = 0; i < iterations; i++ )
            {
                StringReader sr = new StringReader( tokenXml );
                XmlDictionaryReader reader = XmlDictionaryReader.CreateDictionaryReader( XmlReader.Create( sr ) );
                reader.MoveToContent();
                SecurityToken saml2Token = samlTokenHandler.ReadToken( reader );
                samlTokenHandler.ValidateToken( saml2Token );
            }
            if ( display )
            {
                Console.WriteLine( string.Format( validating, "Saml2SecurityTokenHandler", iterations, DateTime.UtcNow - started ) );
            }

            JwtSecurityTokenHandler jwtTokenHandler = new JwtSecurityTokenHandler();
            JwtSecurityToken jwt = jwtTokenHandler.CreateToken( tokenDescriptor ) as JwtSecurityToken;
            jwtTokenHandler.Configuration = tokenHandlerConfiguration;
            started = DateTime.UtcNow;
            for ( int i = 0; i < iterations; i++ )
            {
                jwtTokenHandler.ValidateToken( jwt.RawData );
            }

            if ( display )
            {
                Console.WriteLine( string.Format( validating, "JwtSecurityTokenHandle - ValidateToken( jwt.RawData )", iterations, DateTime.UtcNow - started ) );
            }

            jwt = jwtTokenHandler.CreateToken( tokenDescriptor ) as JwtSecurityToken;
            sb = new StringBuilder();
            writer = XmlWriter.Create(sb);
            jwtTokenHandler.WriteToken( writer, jwt );                                    
            writer.Flush();
            writer.Close();
            tokenXml = sb.ToString();

            started = DateTime.UtcNow;
            for ( int i = 0; i<iterations; i++ )
            {
                StringReader sr = new StringReader( tokenXml );
                XmlDictionaryReader reader = XmlDictionaryReader.CreateDictionaryReader( XmlReader.Create( sr ) );
                reader.MoveToContent();
                SecurityToken jwtToken = jwtTokenHandler.ReadToken( reader );
                jwtTokenHandler.ValidateToken( jwtToken );
            }

            if ( display )
            {
                Console.WriteLine( string.Format( validating, "JwtSecurityTokenHandle - ReadToken( reader ), ValidateToken( jwtToken )", iterations, DateTime.UtcNow - started ) );
            }

            started = DateTime.UtcNow;
            for ( int i = 0; i < iterations; i++ )
            {
                StringReader sr = new StringReader( tokenXml );
                XmlDictionaryReader reader = XmlDictionaryReader.CreateDictionaryReader( XmlReader.Create( sr ) );
                reader.MoveToContent();
                JwtSecurityToken jwtToken = jwtTokenHandler.ReadToken( reader ) as JwtSecurityToken;
                jwtTokenHandler.ValidateToken( jwtToken.RawData );
            }

            if ( display )
            {
                Console.WriteLine( string.Format( validating, "JwtSecurityTokenHandle - ReadToken( reader ), ValidateToken( jwtToken.RawData )", iterations, DateTime.UtcNow - started ) );
            }
        }

        private void RunCreationTests( SecurityTokenDescriptor tokenDescriptor, int iterations, bool display = true )
        {
            // Create jwts using wif
            // Create Saml2 tokens
            // Create Saml tokens

            DateTime started;
            string written = "Created, signed and xmlWrite: '{0}', '{1}' Tokens. Time: '{2}'";
            string created = "Created, signed: '{0}', '{1}' Tokens. Time: '{2}'";

            SignatureProviderFactory factory = new SignatureProviderFactory();
            SignatureProvider signatureProvider = factory.CreateForSigning( tokenDescriptor.SigningCredentials.SigningKey, tokenDescriptor.SigningCredentials.SignatureAlgorithm );

            started = DateTime.UtcNow;
            for ( int i = 0; i < iterations; i++ )
            {
                CreateJwts( tokenDescriptor, signatureProvider );
            }

            if ( display )
            {
                Console.WriteLine( string.Format( created, "JwtHandler - signatureProvider != null", iterations, DateTime.UtcNow - started ) );
            }

            started = DateTime.UtcNow;
            for ( int i = 0; i < iterations; i++ )
            {
                CreateJwts( tokenDescriptor, null );
            }

            if ( display )
            {
                Console.WriteLine( string.Format( created, "JwtHandler - signatureProvider == null", iterations, DateTime.UtcNow - started ) );
            }

            started = DateTime.UtcNow;
            for ( int i = 0; i < iterations; i++ )
            {
                CreateSaml2Tokens( tokenDescriptor );
            }

            if ( display )
            {
                Console.WriteLine( string.Format( written, "Saml2", iterations, DateTime.UtcNow - started ) );
            }

            started = DateTime.UtcNow;
            for ( int i = 0; i < iterations; i++ )
            {
                CreateSamlTokens( tokenDescriptor );
            }

            if ( display )
            {
                Console.WriteLine( string.Format( written, "Saml1", iterations, DateTime.UtcNow - started ) );
            }

            started = DateTime.UtcNow;
            for ( int i = 0; i < iterations; i++ )
            {
                WriteJwts( tokenDescriptor, signatureProvider );
            }

            if ( display )
            {
                Console.WriteLine( string.Format( written, "JwtHandler", iterations, DateTime.UtcNow - started ) );
            }

        }

        private void CreateSaml2Tokens( SecurityTokenDescriptor tokenDescriptor )
        {
            Saml2SecurityTokenHandler samlTokenHandler = new Saml2SecurityTokenHandler();
            Saml2SecurityToken  token = samlTokenHandler.CreateToken( tokenDescriptor ) as Saml2SecurityToken;
            MemoryStream ms = new MemoryStream();
            XmlDictionaryWriter writer = XmlDictionaryWriter.CreateTextWriter( ms );
            samlTokenHandler.WriteToken( writer, token );
        }

        private void CreateSamlTokens( SecurityTokenDescriptor tokenDescriptor )
        {
            SamlSecurityTokenHandler samlTokenHandler = new SamlSecurityTokenHandler();
            SamlSecurityToken token = samlTokenHandler.CreateToken( tokenDescriptor ) as SamlSecurityToken;
            MemoryStream ms = new MemoryStream();
            XmlDictionaryWriter writer = XmlDictionaryWriter.CreateTextWriter( ms );
            samlTokenHandler.WriteToken( writer, token );
        }

        private void WriteJwts( SecurityTokenDescriptor tokenDescriptor, SignatureProvider signatureProvider )
        {
            JwtSecurityTokenHandler tokenHandler = new JwtSecurityTokenHandler();
            JwtSecurityToken jwt = new JwtSecurityToken( tokenDescriptor.TokenIssuerName, tokenDescriptor.AppliesToAddress, tokenDescriptor.Subject.Claims, tokenDescriptor.Lifetime, tokenDescriptor.SigningCredentials );
            MemoryStream ms = new MemoryStream();
            XmlDictionaryWriter writer = XmlDictionaryWriter.CreateTextWriter( ms );
            tokenHandler.WriteToken( writer, jwt );
        }

        private void CreateJwts( SecurityTokenDescriptor tokenDescriptor, SignatureProvider signatureProvider )
        {
            JwtSecurityTokenHandler tokenHandler = new JwtSecurityTokenHandler();
            tokenHandler.CreateToken( issuer: tokenDescriptor.TokenIssuerName,
                                      audience: tokenDescriptor.AppliesToAddress,
                                      subject: tokenDescriptor.Subject,
                                      signingCredentials: tokenDescriptor.SigningCredentials,
                                      signatureProvider: signatureProvider );
        }

    }
}
