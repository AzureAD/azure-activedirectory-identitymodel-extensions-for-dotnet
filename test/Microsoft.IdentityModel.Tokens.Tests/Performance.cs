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

using System;
using System.IdentityModel.Tokens.Jwt;

#if NNET451
using Microsoft.IdentityModel.Tokens.Saml;
using System.IdentityModel.Tokens;
#endif
using System.IO;
using System.Xml;
using Xunit;

namespace Microsoft.IdentityModel.Tokens.Tests
{
    /// <summary>
    /// This test is a good place to grook how to create tokens.
    /// </summary>
    public class PerformanceTests
    {
        [Fact(Skip = "till 5.2.0")]
        public void Jwt_Performance()
        {
            throw new NotImplementedException();
#if POST_REFACTOR
            SecurityTokenDescriptor tokenDescriptor;
            tokenDescriptor = new SecurityTokenDescriptor()
            {
                NotBefore = DateTime.UtcNow,
                Expires = DateTime.UtcNow + TimeSpan.FromDays(1),
                SigningCredentials = KeyingMaterial.RSASigningCreds_2048,
                Claims = Subjects.Simple( Issuers.GotJwt, Issuers.GotJwtOriginal ),
                Issuer = Issuers.GotJwt,
                Audience = Audiences.AuthFactors,
            };

            Console.WriteLine( "\n====================\nAsymmetric" );
            Console.WriteLine( "\n====================\nValidate\n" );

            RunValidationTests( tokenDescriptor, KeyingMaterial.RSASigningCreds_2048, KeyingMaterial.RSASigningCreds_2048, 50, false );
            RunValidationTests( tokenDescriptor, KeyingMaterial.RSASigningCreds_2048, KeyingMaterial.RSASigningCreds_2048, 5000, true );

            Console.WriteLine( "\n====================\nCreate\n" );
            RunCreationTests( tokenDescriptor, 50, false );
            RunCreationTests( tokenDescriptor, 5000 );

            tokenDescriptor = new SecurityTokenDescriptor() 
            {
                NotBefore = DateTime.UtcNow,
                Expires = DateTime.UtcNow + TimeSpan.FromDays(1),
                SigningCredentials = KeyingMaterial.SymmetricSigningCreds_256_Sha2,
                Claims = Subjects.Simple( Issuers.GotJwt, Issuers.GotJwtOriginal ),
                Issuer = Issuers.GotJwt,
                Audience = Audiences.AuthFactors,
            };

            Console.WriteLine( "\n================\nSymmetric" );
            Console.WriteLine( "\n====================\nValidate\n" );
            RunValidationTests( tokenDescriptor, KeyingMaterial.BinarySecretToken_256, KeyingMaterial.SymmetricSecurityKey_256, 50, false );
            RunValidationTests( tokenDescriptor, KeyingMaterial.BinarySecretToken_256, KeyingMaterial.SymmetricSecurityKey_256, 10000, true );

            Console.WriteLine( "\n====================\nCreate\n" );
            RunCreationTests( tokenDescriptor, 100, false );
            RunCreationTests( tokenDescriptor, 10000 );
#endif
        }

        private void RunValidationTests( SecurityTokenDescriptor tokenDescriptor, SecurityKey key, int iterations, bool display = true )
        {
            throw new NotImplementedException();

#if POST_REFACTOR
            // Create jwts using wif
            // Create Saml2 tokens
            // Create Saml tokens

            DateTime started;
            string validating = "Validating, signed: '{0}', '{1}' Tokens. Time: '{2}'";


           
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
#endif
        }

        private void RunCreationTests( SecurityTokenDescriptor tokenDescriptor, int iterations, bool display = true )
        {
            // Create jwts using wif
            // Create Saml2 tokens
            // Create Saml tokens

            DateTime started;
            string written = "Created, signed and xmlWrite: '{0}', '{1}' Tokens. Time: '{2}'";
            string created = "Created, signed: '{0}', '{1}' Tokens. Time: '{2}'";

            started = DateTime.UtcNow;
            for ( int i = 0; i < iterations; i++ )
            {
                (new JwtSecurityTokenHandler()).CreateJwtSecurityToken(tokenDescriptor);
            }

            if ( display )
            {
                Console.WriteLine( string.Format( created, "JwtHandler - signatureProvider != null", iterations, DateTime.UtcNow - started ) );
            }

            started = DateTime.UtcNow;
            for ( int i = 0; i < iterations; i++ )
            {
                (new JwtSecurityTokenHandler()).CreateJwtSecurityToken(tokenDescriptor);
            }

            if ( display )
            {
                Console.WriteLine( string.Format( created, "JwtHandler - signatureProvider == null", iterations, DateTime.UtcNow - started ) );
            }
#if NNET451
            started = DateTime.UtcNow;
            for ( int i = 0; i < iterations; i++ )
            {
                // TODO - populate descriptor
                var descriptor2 = new System.IdentityModel.Tokens.SecurityTokenDescriptor();
                CreateSaml2Tokens( descriptor2 );
            }

            if ( display )
            {
                Console.WriteLine( string.Format( written, "Saml2", iterations, DateTime.UtcNow - started ) );
            }

            started = DateTime.UtcNow;
            for ( int i = 0; i < iterations; i++ )
            {
                // TODO - populate descriptor
                var descriptor = new System.IdentityModel.Tokens.SecurityTokenDescriptor();
                CreateSamlTokens( descriptor );
            }

            if ( display )
            {
                Console.WriteLine( string.Format( written, "Saml1", iterations, DateTime.UtcNow - started ) );
            }
#endif
            started = DateTime.UtcNow;
            for ( int i = 0; i < iterations; i++ )
            {
                (new JwtSecurityTokenHandler()).CreateEncodedJwt(tokenDescriptor);
            }

            if ( display )
            {
                Console.WriteLine( string.Format( written, "JwtHandler", iterations, DateTime.UtcNow - started ) );
            }

        }

#if NNET451
        private void CreateSaml2Tokens( System.IdentityModel.Tokens.SecurityTokenDescriptor tokenDescriptor )
        {
            var samlTokenHandler = new System.IdentityModel.Tokens.Saml2SecurityTokenHandler();
            var  token = samlTokenHandler.CreateToken( tokenDescriptor ) as Saml2SecurityToken;
            MemoryStream ms = new MemoryStream();
            XmlDictionaryWriter writer = XmlDictionaryWriter.CreateTextWriter( ms );
            samlTokenHandler.WriteToken( writer, token );
        }

        private void CreateSamlTokens( System.IdentityModel.Tokens.SecurityTokenDescriptor tokenDescriptor )
        {
            var samlTokenHandler = new System.IdentityModel.Tokens.SamlSecurityTokenHandler();
            var token = samlTokenHandler.CreateToken( tokenDescriptor ) as SamlSecurityToken;
            MemoryStream ms = new MemoryStream();
            XmlDictionaryWriter writer = XmlDictionaryWriter.CreateTextWriter( ms );
            samlTokenHandler.WriteToken( writer, token );
        }
#endif
    }
}
