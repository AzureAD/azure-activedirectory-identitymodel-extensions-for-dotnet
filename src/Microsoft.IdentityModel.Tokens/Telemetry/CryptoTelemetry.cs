// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.


using Microsoft.IdentityModel.Tokens;

namespace Microsoft.IdentityModel.Telemetry
{
    internal static class CryptoTelemetry
    {
        private static class KeyAlgorithmIds
        {
            public const string Rsa2048 = "RSA-2048";
            public const string Rsa3072 = "RSA-3072";
            public const string Rsa4096 = "RSA-4096";

            public const string EcdsaP256 = "ECDSA-P256";
            public const string EcdsaP384 = "ECDSA-P384";
            public const string EcdsaP521 = "ECDSA-P521";

            public const string Symmetric128 = "SYM-128";
            public const string Symmetric192 = "SYM-192";
            public const string Symmetric256 = "SYM-256";
            public const string Symmetric384 = "SYM-384";
            public const string Symmetric512 = "SYM-512";

            public const string Unknown = "UNKNOWN";
            public const string NoKey = "NO-KEY"; // Used when no key is found or provided to differentiate from unknown key types
        }

        internal static string GetKeyAlgorithmId(SecurityKey key)
        {
            if (key == null)
                return KeyAlgorithmIds.NoKey;

            if (key is RsaSecurityKey rsa)
            {
                return rsa.KeySize switch
                {
                    2048 => KeyAlgorithmIds.Rsa2048,
                    3072 => KeyAlgorithmIds.Rsa3072,
                    4096 => KeyAlgorithmIds.Rsa4096,
                    _ => KeyAlgorithmIds.Unknown
                };
            }

            if (key is ECDsaSecurityKey ecdsa)
            {
                return ecdsa.KeySize switch
                {
                    256 => KeyAlgorithmIds.EcdsaP256,
                    384 => KeyAlgorithmIds.EcdsaP384,
                    521 => KeyAlgorithmIds.EcdsaP521,
                    _ => KeyAlgorithmIds.Unknown
                };
            }

            if (key is SymmetricSecurityKey symmetric)
            {
                return symmetric.KeySize switch
                {
                    128 => KeyAlgorithmIds.Symmetric128,
                    192 => KeyAlgorithmIds.Symmetric192,
                    256 => KeyAlgorithmIds.Symmetric256,
                    384 => KeyAlgorithmIds.Symmetric384,
                    512 => KeyAlgorithmIds.Symmetric512,
                    _ => KeyAlgorithmIds.Unknown
                };
            }

            if (key is JsonWebKey jwk)
            {
                // If the JsonWebKey has been converted to a typed key, use that
                if (jwk.ConvertedSecurityKey != null)
                {
                    return GetKeyAlgorithmId(jwk.ConvertedSecurityKey);
                }

                // Otherwise, check the key type
                if (jwk.Kty == JsonWebAlgorithmsKeyTypes.RSA)
                {
                    return jwk.KeySize switch
                    {
                        2048 => KeyAlgorithmIds.Rsa2048,
                        3072 => KeyAlgorithmIds.Rsa3072,
                        4096 => KeyAlgorithmIds.Rsa4096,
                        _ => KeyAlgorithmIds.Unknown
                    };
                }
                else if (jwk.Kty == JsonWebAlgorithmsKeyTypes.EllipticCurve)
                {
                    return jwk.KeySize switch
                    {
                        256 => KeyAlgorithmIds.EcdsaP256,
                        384 => KeyAlgorithmIds.EcdsaP384,
                        521 => KeyAlgorithmIds.EcdsaP521,
                        _ => KeyAlgorithmIds.Unknown
                    };
                }
                else if (jwk.Kty == JsonWebAlgorithmsKeyTypes.Octet)
                {
                    return jwk.KeySize switch
                    {
                        128 => KeyAlgorithmIds.Symmetric128,
                        192 => KeyAlgorithmIds.Symmetric192,
                        256 => KeyAlgorithmIds.Symmetric256,
                        384 => KeyAlgorithmIds.Symmetric384,
                        512 => KeyAlgorithmIds.Symmetric512,
                        _ => KeyAlgorithmIds.Unknown
                    };
                }
            }

            if (key is X509SecurityKey x509)
            {
                // X509SecurityKey wraps an RSA or ECDsa key
                // Key sizes don't overlap: RSA (2048/3072/4096) vs ECDsa (256/384/521)
                return x509.KeySize switch
                {
                    // RSA key sizes
                    2048 => KeyAlgorithmIds.Rsa2048,
                    3072 => KeyAlgorithmIds.Rsa3072,
                    4096 => KeyAlgorithmIds.Rsa4096,
                    // ECDsa key sizes
                    256 => KeyAlgorithmIds.EcdsaP256,
                    384 => KeyAlgorithmIds.EcdsaP384,
                    521 => KeyAlgorithmIds.EcdsaP521,
                    _ => KeyAlgorithmIds.Unknown
                };
            }

            // EdDSA, MLDSA and other key types can be added here when needed.

            return KeyAlgorithmIds.Unknown;
        }
    }
}
