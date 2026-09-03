// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;

#pragma warning disable SYSLIB5006 // CompositeMLDsa is experimental

namespace Microsoft.IdentityModel.TestUtils
{
    /// <summary>
    /// Composite ML-DSA test keying material. All members are lazily initialized.
    /// Callers should check <see cref="IsAlgorithmSupported"/> before accessing key material.
    /// </summary>
    public static class CompositeMLDsaKeyingMaterial
    {
        public static bool IsAlgorithmSupported(string algorithm)
        {
            if (!CompositeMLDsa.IsSupported) return false;
            var bcl = GetCompositeMLDsaAlgorithmOrNull(algorithm);
            return bcl != null && CompositeMLDsa.IsAlgorithmSupported(bcl);
        }

        /// <summary>
        /// Maps a JOSE composite algorithm string to the BCL algorithm, or null if unknown.
        /// </summary>
        public static CompositeMLDsaAlgorithm GetCompositeMLDsaAlgorithmOrNull(string algorithm)
        {
            return algorithm switch
            {
                SecurityAlgorithms.MlDsa44WithECDsaP256 => CompositeMLDsaAlgorithm.MLDsa44WithECDsaP256,
                SecurityAlgorithms.MlDsa65WithECDsaP256 => CompositeMLDsaAlgorithm.MLDsa65WithECDsaP256,
                SecurityAlgorithms.MlDsa87WithECDsaP384 => CompositeMLDsaAlgorithm.MLDsa87WithECDsaP384,
                _ => null
            };
        }

        // Lazily generated composite keys — one private+public pair per algorithm.
        private static CompositeMLDsaSecurityKey _compositeMLDsa44ES256Key;
        private static CompositeMLDsaSecurityKey _compositeMLDsa65ES256Key;
        private static CompositeMLDsaSecurityKey _compositeMLDsa87ES384Key;

        internal static CompositeMLDsaSecurityKey CompositeMLDsa44ES256Key =>
            _compositeMLDsa44ES256Key ??= new CompositeMLDsaSecurityKey(
                CompositeMLDsa.GenerateKey(CompositeMLDsaAlgorithm.MLDsa44WithECDsaP256));

        internal static CompositeMLDsaSecurityKey CompositeMLDsa65ES256Key =>
            _compositeMLDsa65ES256Key ??= new CompositeMLDsaSecurityKey(
                CompositeMLDsa.GenerateKey(CompositeMLDsaAlgorithm.MLDsa65WithECDsaP256));

        internal static CompositeMLDsaSecurityKey CompositeMLDsa87ES384Key =>
            _compositeMLDsa87ES384Key ??= new CompositeMLDsaSecurityKey(
                CompositeMLDsa.GenerateKey(CompositeMLDsaAlgorithm.MLDsa87WithECDsaP384));

        // Corresponding public-only keys.
        private static CompositeMLDsaSecurityKey _compositeMLDsa44ES256KeyPublic;
        private static CompositeMLDsaSecurityKey _compositeMLDsa65ES256KeyPublic;
        private static CompositeMLDsaSecurityKey _compositeMLDsa87ES384KeyPublic;

        internal static CompositeMLDsaSecurityKey CompositeMLDsa44ES256Key_Public =>
            _compositeMLDsa44ES256KeyPublic ??= CreatePublicOnlyKey(CompositeMLDsa44ES256Key);

        internal static CompositeMLDsaSecurityKey CompositeMLDsa65ES256Key_Public =>
            _compositeMLDsa65ES256KeyPublic ??= CreatePublicOnlyKey(CompositeMLDsa65ES256Key);

        internal static CompositeMLDsaSecurityKey CompositeMLDsa87ES384Key_Public =>
            _compositeMLDsa87ES384KeyPublic ??= CreatePublicOnlyKey(CompositeMLDsa87ES384Key);

        internal static CompositeMLDsaSecurityKey CreatePublicOnlyKey(CompositeMLDsaSecurityKey privateKey)
        {
            byte[] pubBytes = privateKey.CompositeMLDsa.ExportCompositeMLDsaPublicKey();
            return new CompositeMLDsaSecurityKey(
                CompositeMLDsa.ImportCompositeMLDsaPublicKey(privateKey.CompositeMLDsa.Algorithm, pubBytes));
        }

        internal static CompositeMLDsaSecurityKey GetPrivateKey(string algorithm) => algorithm switch
        {
            SecurityAlgorithms.MlDsa44WithECDsaP256 => CompositeMLDsa44ES256Key,
            SecurityAlgorithms.MlDsa65WithECDsaP256 => CompositeMLDsa65ES256Key,
            SecurityAlgorithms.MlDsa87WithECDsaP384 => CompositeMLDsa87ES384Key,
            _ => throw new ArgumentException($"Unknown composite algorithm: {algorithm}", nameof(algorithm))
        };

        internal static CompositeMLDsaSecurityKey GetPublicKey(string algorithm) => algorithm switch
        {
            SecurityAlgorithms.MlDsa44WithECDsaP256 => CompositeMLDsa44ES256Key_Public,
            SecurityAlgorithms.MlDsa65WithECDsaP256 => CompositeMLDsa65ES256Key_Public,
            SecurityAlgorithms.MlDsa87WithECDsaP384 => CompositeMLDsa87ES384Key_Public,
            _ => throw new ArgumentException($"Unknown composite algorithm: {algorithm}", nameof(algorithm))
        };
    }
}
