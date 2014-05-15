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

using System;
using System.Collections.Generic;
using System.IdentityModel.Selectors;
using System.IdentityModel.Tokens;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.ServiceModel.Security.Tokens;

namespace Microsoft.IdentityModel.Test
{
    public class KeyingMaterial
    {
        // all asymmetric material has private key unless public is included in variable name
        public const string CertPassword = "abcd";

        public const string X509Data_Public_AAD =@"MIIDPjCCAiqgAwIBAgIQVWmXY/+9RqFA/OG9kFulHDAJBgUrDgMCHQUAMC0xKzApBgNVBAMTImFjY291bnRzLmFjY2Vzc2NvbnRyb2wud2luZG93cy5uZXQwHhcNMTIwNjA3MDcwMDAwWhcNMTQwNjA3MDcwMDAwWjAtMSswKQYDVQQDEyJhY2NvdW50cy5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArCz8Sn3GGXmikH2MdTeGY1D711EORX/lVXpr+ecGgqfUWF8MPB07XkYuJ54DAuYT318+2XrzMjOtqkT94VkXmxv6dFGhG8YZ8vNMPd4tdj9c0lpvWQdqXtL1TlFRpD/P6UMEigfN0c9oWDg9U7Ilymgei0UXtf1gtcQbc5sSQU0S4vr9YJp2gLFIGK11Iqg4XSGdcI0QWLLkkC6cBukhVnd6BCYbLjTYy3fNs4DzNdemJlxGl8sLexFytBF6YApvSdus3nFXaMCtBGx16HzkK9ne3lobAwL2o79bP4imEGqg+ibvyNmbrwFGnQrBc1jTF9LyQX9q+louxVfHs6ZiVwIDAQABo2IwYDBeBgNVHQEEVzBVgBCxDDsLd8xkfOLKm4Q/SzjtoS8wLTErMCkGA1UEAxMiYWNjb3VudHMuYWNjZXNzY29udHJvbC53aW5kb3dzLm5ldIIQVWmXY/+9RqFA/OG9kFulHDAJBgUrDgMCHQUAA4IBAQAkJtxxm/ErgySlNk69+1odTMP8Oy6L0H17z7XGG3w4TqvTUSWaxD4hSFJ0e7mHLQLQD7oV/erACXwSZn2pMoZ89MBDjOMQA+e6QzGB7jmSzPTNmQgMLA8fWCfqPrz6zgH+1F1gNp8hJY57kfeVPBiyjuBmlTEBsBlzolY9dd/55qqfQk6cgSeCbHCy/RU/iep0+UsRMlSgPNNmqhj5gmN2AFVCN96zF694LwuPae5CeR2ZcVknexOWHYjFM0MgUSw0ubnGl0h9AJgGyhvNGcjQqu9vd1xkupFgaN+f7P3p3EVN5csBg5H94jEcQZT7EKeTiZ6bTrpDAnrr8tDCy8ng";
        public const string X509Data_LocalSts =  @"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";
        public static X509Certificate2 Cert_LocalSts = new X509Certificate2( Convert.FromBase64String( X509Data_LocalSts ), CertPassword, X509KeyStorageFlags.MachineKeySet );
        public static X509SecurityToken X509Token_LocalSts = new X509SecurityToken( Cert_LocalSts );
        public static X509SigningCredentials X509SigningCreds_LocalSts  = new X509SigningCredentials( Cert_LocalSts );
        public static X509AsymmetricSecurityKey AsymmetricKey_LocalSts = X509Token_LocalSts.SecurityKeys[0] as X509AsymmetricSecurityKey;

        // 1024 bit RSA
        public const string X509Data_1024 = @"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";
        public static X509Certificate2 Cert_1024 = new X509Certificate2( Convert.FromBase64String( X509Data_1024 ), CertPassword, X509KeyStorageFlags.MachineKeySet );
        public static X509SecurityToken X509Token_1024 = new X509SecurityToken( Cert_1024 );
        public static X509SigningCredentials X509SigningCreds_1024_RsaSha2_Sha2  = new X509SigningCredentials( Cert_1024, SecurityAlgorithms.RsaSha256Signature, SecurityAlgorithms.Sha256Digest );
        public static X509AsymmetricSecurityKey AsymmetricKey_1024 = X509Token_1024.SecurityKeys[0] as X509AsymmetricSecurityKey;

        // 2048 bit RSA
        public const string DefaultX509Data_2048 = @"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";
        public static X509Certificate2 DefaultCert_2048 = new X509Certificate2( Convert.FromBase64String( DefaultX509Data_2048 ), CertPassword, X509KeyStorageFlags.MachineKeySet );
        public static X509SecurityToken DefaultX509Token_2048 = new X509SecurityToken( DefaultCert_2048 );
        public static X509SigningCredentials DefaultX509SigningCreds_2048_RsaSha2_Sha2  = new X509SigningCredentials( DefaultCert_2048, SecurityAlgorithms.RsaSha256Signature, SecurityAlgorithms.Sha256Digest );
        public static X509Certificate2 DefaultAsymmetricCert_2048 = new X509Certificate2( Convert.FromBase64String( DefaultX509Data_2048 ), CertPassword, X509KeyStorageFlags.MachineKeySet );
        public static X509SecurityToken DefaultAsymmetricX509Token_2048 = new X509SecurityToken( DefaultCert_2048 );
        public static X509SigningCredentials DefaultAsymmetricSigningCreds_2048_RsaSha2_Sha2  = new X509SigningCredentials( DefaultCert_2048, SecurityAlgorithms.RsaSha256Signature, SecurityAlgorithms.Sha256Digest );
        public static X509AsymmetricSecurityKey AsymmetricKey_2048 = DefaultX509Token_2048.SecurityKeys[0] as X509AsymmetricSecurityKey;

        public static string DefaultX509Data_Public_2048                          = @"MIICyjCCAbKgAwIBAgIQJPMYqnyiTY1GQYAwZxadMjANBgkqhkiG9w0BAQsFADAhMR8wHQYDVQQDExZBREZTIFNpZ25pbmcgLSBTVFMuY29tMB4XDTEyMTAwOTIyMTA0OVoXDTEzMTAwOTIyMTA0OVowITEfMB0GA1UEAxMWQURGUyBTaWduaW5nIC0gU1RTLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMmeVPJz8o7ayB3AS2dJtsIo/eXqeNhZ+ZqEJgHVHc0JAAgNNwR++moMt8+iIlOKZiAL8dvQBKOuPms+FfqrG1HshnMiLcuadtWUqOntxUdyQLcEKvdaFOqOppqmasqGFtRLPwYKIkZOkj8ikndNzI6PZV46mw18nLaN6rTByMnjVA5n9Lf7Cdu7lmxlKGJOI5F0IfeaW68/kY1bdw3KAEb1aOKHj0r7RJ2joRuHJ+96kw1bA2T6bGC/1LYND3DFsnQQtMBl7LlDrSG1gGoiZxCoQmPCxfrTCrYKGK6y9j6IQ4MCmJpnt0l/INL5i88TjctF4IkJwbJGn9iY2fIIBxMCAwEAATANBgkqhkiG9w0BAQsFAAOCAQEAq/SyHGCLpBm+Gmh5I7BAWJXvtPaIelt30WgKVXRHccxRVIYpKOfAA2iPuD/CVruFz6pnP4K7o2KLAs+XJptigYzLEjKw6rY4836ZJC8m5kfBVanu45OW39nxzxp1udbxQ5gAdmvnY/2agpFhCFR8M1BtWON6G3SzHwo2dXHh+ettOO2LtK38e1+Uy+KGowRw/m4gprSIvgN3AAo7e0PnFblZn6vRgMsK60QB5D8f+Kxdg2I3ZGQcPBQI2fpjEDQCZVc2LV4ywPX4QDPfmYjn+1IaU9w7unbh+oUGQsrdKw3gsdzWEsX/IMXTDf46FEOjV+JqE7VilzcNuDcQ0x9K8gAA";
        public static X509Certificate2 DefaultCertPublic_2048                    = new X509Certificate2( Convert.FromBase64String( DefaultX509Data_Public_2048 ) );
        public static X509SecurityToken DefaultX509Token_Public_2048             = new X509SecurityToken( DefaultCertPublic_2048 );
        public static X509AsymmetricSecurityKey DefaultAsymmetricKey_Public_2048 = DefaultX509Token_Public_2048.SecurityKeys[0] as X509AsymmetricSecurityKey;
        public static SigningCredentials DefaultX509SigningCreds_Public_2048_RsaSha2_Sha2     = new SigningCredentials( DefaultAsymmetricKey_Public_2048, SecurityAlgorithms.RsaSha256Signature, SecurityAlgorithms.Sha256Digest );

        public static string DefaultSymmetricKeyEncoded_256                    ="Vbxq2mlbGJw8XH+ZoYBnUHmHga8/o/IduvU/Tht70iE=";
        public static byte[] DefaultSymmetricKeyBytes_256                      = Convert.FromBase64String( DefaultSymmetricKeyEncoded_256 );
        public static SymmetricSecurityKey DefaultSymmetricSecurityKey_256     = new InMemorySymmetricSecurityKey( DefaultSymmetricKeyBytes_256 );
        public static BinarySecretSecurityToken  DefaultSymmetricSecurityToken_256  = new BinarySecretSecurityToken( DefaultSymmetricKeyBytes_256 );
        public static SigningCredentials DefaultSymmetricSigningCreds_256_Sha2 = new SigningCredentials( DefaultSymmetricSecurityKey_256, SecurityAlgorithms.HmacSha256Signature, SecurityAlgorithms.Sha256Digest );

        // used in negative cases
        public static string SymmetricKeyEncoded2_256                     ="VbbbbmlbGJw8XH+ZoYBnUHmHga8/o/IduvU/Tht70iE=";
        public static byte[] SymmetricKeyBytes2_256                       = Convert.FromBase64String( SymmetricKeyEncoded2_256 );
        public static SymmetricSecurityKey SymmetricSecurityKey2_256               = new InMemorySymmetricSecurityKey( SymmetricKeyBytes2_256 );
        public static BinarySecretSecurityToken  BinarySecretToken2_256   = new BinarySecretSecurityToken( SymmetricKeyBytes2_256 );

        // RSA token
        public static RsaSecurityToken RsaToken_2048 = new RsaSecurityToken( AsymmetricKey_2048.GetAsymmetricAlgorithm( SecurityAlgorithms.RsaSha256Signature, false ) as RSA );
        public static RsaSecurityKey AsymmetricKey_Rsa_2048 = RsaToken_2048.SecurityKeys[0] as RsaSecurityKey;
        public static SigningCredentials RSASigningCreds_2048  = new SigningCredentials( AsymmetricKey_Rsa_2048, SecurityAlgorithms.RsaSha256Signature, SecurityAlgorithms.Sha256Digest );

        // These signingCreds have algorithms and hashs that are not supported
        public static SigningCredentials SymmetricSigningCreds_256_Rsa256_Sha2      = new SigningCredentials( DefaultSymmetricSecurityKey_256, SecurityAlgorithms.RsaSha256Signature, SecurityAlgorithms.Sha256Digest );
        public static SigningCredentials SymmetricSigningCreds_256_Rsa256_Sha1      = new SigningCredentials( DefaultSymmetricSecurityKey_256, SecurityAlgorithms.RsaSha256Signature, SecurityAlgorithms.Sha1Digest );
        public static SigningCredentials SymmetricSigningCreds_2048RSA_H256_Sha2    = new SigningCredentials( RsaToken_2048.SecurityKeys[0], SecurityAlgorithms.HmacSha256Signature, SecurityAlgorithms.Sha256Digest );

        // Small Key
        public static BinarySecretSecurityToken BinarayToken56BitKey        = new BinarySecretSecurityToken( 56 );

        public static IEnumerable<SecurityToken> AsymmetricTokens
        {
            get
            {
                yield return X509Token_1024;
                yield return DefaultX509Token_2048;
                yield return DefaultX509Token_Public_2048;
                yield return RsaToken_2048;
            }
        }
        public static SecurityTokenResolver AsymmetricSecurityTokenResolver
        {
            get
            {
                List<SecurityToken> tokens = new List<SecurityToken>(AsymmetricTokens);
                return SecurityTokenResolver.CreateDefaultSecurityTokenResolver(tokens.AsReadOnly(), true);
            }
        }

        public static IssuerNameRegistry AsymmetricIssuerNameRegistry
        {
            get
            {
                ConfigurationBasedIssuerNameRegistry cbinr = new ConfigurationBasedIssuerNameRegistry();
                foreach (SecurityToken token in AsymmetricTokens)
                {
                    X509SecurityToken x509Token = token as X509SecurityToken;
                    if (x509Token != null)
                    {
                        if (!cbinr.ConfiguredTrustedIssuers.ContainsKey(x509Token.Certificate.GetCertHashString()))
                        {
                            cbinr.AddTrustedIssuer(x509Token.Certificate.GetCertHashString(), x509Token.Certificate.Subject);
                        }
                    }
                }

                return cbinr;
            }
        }
    }
}