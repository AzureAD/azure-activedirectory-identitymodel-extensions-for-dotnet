// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma warning disable MSIDENT2001 // Wilson experimental composite ML-DSA APIs
#pragma warning disable SYSLIB5006  // .NET experimental CompositeMLDsa types

using System;
using System.Security.Cryptography;
using System.Text;
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Configs;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Tokens.Pqc.Composite;

namespace Microsoft.IdentityModel.Benchmarks;

// dotnet run -c release -f net10.0 --filter Microsoft.IdentityModel.Benchmarks.CompositeMLDsaSignatureBenchmarks.*

/// <summary>
/// Compares raw sign/verify performance across algorithm families:
/// RSA-2048 (baseline), ECDSA P-256, pure ML-DSA, and composite ML-DSA.
/// </summary>
[GroupBenchmarksBy(BenchmarkLogicalGroupRule.ByCategory)]
[CategoriesColumn]
public class CompositeMLDsaSignatureBenchmarks
{
    private byte[] _dataToSign;

    // Signing providers
    private SignatureProvider _rsaSha256SignProvider;
    private SignatureProvider _ecdsaP256SignProvider;
    private SignatureProvider _mlDsa44SignProvider;
    private SignatureProvider _mlDsa65SignProvider;
    private SignatureProvider _mlDsa87SignProvider;
    private CompositeMLDsaSignatureProvider _composite44Es256SignProvider;
    private CompositeMLDsaSignatureProvider _composite65Es256SignProvider;
    private CompositeMLDsaSignatureProvider _composite87Es384SignProvider;

    // Verification providers
    private SignatureProvider _rsaSha256VerifyProvider;
    private SignatureProvider _ecdsaP256VerifyProvider;
    private SignatureProvider _mlDsa44VerifyProvider;
    private SignatureProvider _mlDsa65VerifyProvider;
    private SignatureProvider _mlDsa87VerifyProvider;
    private CompositeMLDsaSignatureProvider _composite44Es256VerifyProvider;
    private CompositeMLDsaSignatureProvider _composite65Es256VerifyProvider;
    private CompositeMLDsaSignatureProvider _composite87Es384VerifyProvider;

    // Pre-computed signatures for verification benchmarks
    private byte[] _rsaSha256Signature;
    private byte[] _ecdsaP256Signature;
    private byte[] _mlDsa44Signature;
    private byte[] _mlDsa65Signature;
    private byte[] _mlDsa87Signature;
    private byte[] _composite44Es256Signature;
    private byte[] _composite65Es256Signature;
    private byte[] _composite87Es384Signature;

    [GlobalSetup]
    public void Setup()
    {
        // Representative JWT-sized payload (~200 bytes base64url-encoded header.payload)
        string header = @"{""alg"":""RS256"",""typ"":""JWT""}";
        string encodedHeader = Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(header));
        long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        string payload = $@"{{""iss"":""bench-issuer"",""aud"":""bench-audience"",""sub"":""bench-user"",""iat"":{now},""exp"":{now + 3600}}}";
        string encodedPayload = Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(payload));
        _dataToSign = Encoding.ASCII.GetBytes($"{encodedHeader}.{encodedPayload}");

        var cpf = new CryptoProviderFactory { CacheSignatureProviders = false };

        // RSA-2048
        var rsaKey = BenchmarkUtils.RsaSecurityKey;
        _rsaSha256SignProvider = cpf.CreateForSigning(rsaKey, SecurityAlgorithms.RsaSha256);
        _rsaSha256VerifyProvider = cpf.CreateForVerifying(rsaKey, SecurityAlgorithms.RsaSha256);

        // ECDSA P-256
        var ecdsaKey = new ECDsaSecurityKey(ECDsa.Create(ECCurve.NamedCurves.nistP256));
        _ecdsaP256SignProvider = cpf.CreateForSigning(ecdsaKey, SecurityAlgorithms.EcdsaSha256);
        _ecdsaP256VerifyProvider = cpf.CreateForVerifying(ecdsaKey, SecurityAlgorithms.EcdsaSha256);

        // Pure ML-DSA
        var mlDsa44Key = new MlDsaSecurityKey(MLDsa.GenerateKey(MLDsaAlgorithm.MLDsa44));
        var mlDsa65Key = new MlDsaSecurityKey(MLDsa.GenerateKey(MLDsaAlgorithm.MLDsa65));
        var mlDsa87Key = new MlDsaSecurityKey(MLDsa.GenerateKey(MLDsaAlgorithm.MLDsa87));
        _mlDsa44SignProvider = cpf.CreateForSigning(mlDsa44Key, SecurityAlgorithms.MlDsa44);
        _mlDsa65SignProvider = cpf.CreateForSigning(mlDsa65Key, SecurityAlgorithms.MlDsa65);
        _mlDsa87SignProvider = cpf.CreateForSigning(mlDsa87Key, SecurityAlgorithms.MlDsa87);
        _mlDsa44VerifyProvider = cpf.CreateForVerifying(mlDsa44Key, SecurityAlgorithms.MlDsa44);
        _mlDsa65VerifyProvider = cpf.CreateForVerifying(mlDsa65Key, SecurityAlgorithms.MlDsa65);
        _mlDsa87VerifyProvider = cpf.CreateForVerifying(mlDsa87Key, SecurityAlgorithms.MlDsa87);

        // Composite ML-DSA (via ICryptoProvider extensibility)
        var comp44Key = new CompositeMLDsaSecurityKey(
            CompositeMLDsa.GenerateKey(CompositeMLDsaAlgorithm.MLDsa44WithECDsaP256));
        var comp65Key = new CompositeMLDsaSecurityKey(
            CompositeMLDsa.GenerateKey(CompositeMLDsaAlgorithm.MLDsa65WithECDsaP256));
        var comp87Key = new CompositeMLDsaSecurityKey(
            CompositeMLDsa.GenerateKey(CompositeMLDsaAlgorithm.MLDsa87WithECDsaP384));

        _composite44Es256SignProvider = new CompositeMLDsaSignatureProvider(comp44Key, CompositeMLDsaAlgorithms.MlDsa44Es256, true);
        _composite65Es256SignProvider = new CompositeMLDsaSignatureProvider(comp65Key, CompositeMLDsaAlgorithms.MlDsa65Es256, true);
        _composite87Es384SignProvider = new CompositeMLDsaSignatureProvider(comp87Key, CompositeMLDsaAlgorithms.MlDsa87Es384, true);
        _composite44Es256VerifyProvider = new CompositeMLDsaSignatureProvider(comp44Key, CompositeMLDsaAlgorithms.MlDsa44Es256, false);
        _composite65Es256VerifyProvider = new CompositeMLDsaSignatureProvider(comp65Key, CompositeMLDsaAlgorithms.MlDsa65Es256, false);
        _composite87Es384VerifyProvider = new CompositeMLDsaSignatureProvider(comp87Key, CompositeMLDsaAlgorithms.MlDsa87Es384, false);

        // Pre-compute signatures for verification benchmarks
        _rsaSha256Signature = _rsaSha256SignProvider.Sign(_dataToSign);
        _ecdsaP256Signature = _ecdsaP256SignProvider.Sign(_dataToSign);
        _mlDsa44Signature = _mlDsa44SignProvider.Sign(_dataToSign);
        _mlDsa65Signature = _mlDsa65SignProvider.Sign(_dataToSign);
        _mlDsa87Signature = _mlDsa87SignProvider.Sign(_dataToSign);
        _composite44Es256Signature = _composite44Es256SignProvider.Sign(_dataToSign);
        _composite65Es256Signature = _composite65Es256SignProvider.Sign(_dataToSign);
        _composite87Es384Signature = _composite87Es384SignProvider.Sign(_dataToSign);
    }

    // -------- Sign --------

    [BenchmarkCategory("Sign"), Benchmark(Baseline = true)]
    public byte[] Sign_RSA2048_SHA256() => _rsaSha256SignProvider.Sign(_dataToSign);

    [BenchmarkCategory("Sign"), Benchmark]
    public byte[] Sign_ECDSA_P256() => _ecdsaP256SignProvider.Sign(_dataToSign);

    [BenchmarkCategory("Sign"), Benchmark]
    public byte[] Sign_MLDsa44() => _mlDsa44SignProvider.Sign(_dataToSign);

    [BenchmarkCategory("Sign"), Benchmark]
    public byte[] Sign_MLDsa65() => _mlDsa65SignProvider.Sign(_dataToSign);

    [BenchmarkCategory("Sign"), Benchmark]
    public byte[] Sign_MLDsa87() => _mlDsa87SignProvider.Sign(_dataToSign);

    [BenchmarkCategory("Sign"), Benchmark]
    public byte[] Sign_Composite_MLDsa44_ES256() => _composite44Es256SignProvider.Sign(_dataToSign);

    [BenchmarkCategory("Sign"), Benchmark]
    public byte[] Sign_Composite_MLDsa65_ES256() => _composite65Es256SignProvider.Sign(_dataToSign);

    [BenchmarkCategory("Sign"), Benchmark]
    public byte[] Sign_Composite_MLDsa87_ES384() => _composite87Es384SignProvider.Sign(_dataToSign);

    // -------- Verify --------

    [BenchmarkCategory("Verify"), Benchmark(Baseline = true)]
    public bool Verify_RSA2048_SHA256() => _rsaSha256VerifyProvider.Verify(_dataToSign, _rsaSha256Signature);

    [BenchmarkCategory("Verify"), Benchmark]
    public bool Verify_ECDSA_P256() => _ecdsaP256VerifyProvider.Verify(_dataToSign, _ecdsaP256Signature);

    [BenchmarkCategory("Verify"), Benchmark]
    public bool Verify_MLDsa44() => _mlDsa44VerifyProvider.Verify(_dataToSign, _mlDsa44Signature);

    [BenchmarkCategory("Verify"), Benchmark]
    public bool Verify_MLDsa65() => _mlDsa65VerifyProvider.Verify(_dataToSign, _mlDsa65Signature);

    [BenchmarkCategory("Verify"), Benchmark]
    public bool Verify_MLDsa87() => _mlDsa87VerifyProvider.Verify(_dataToSign, _mlDsa87Signature);

    [BenchmarkCategory("Verify"), Benchmark]
    public bool Verify_Composite_MLDsa44_ES256() => _composite44Es256VerifyProvider.Verify(_dataToSign, _composite44Es256Signature);

    [BenchmarkCategory("Verify"), Benchmark]
    public bool Verify_Composite_MLDsa65_ES256() => _composite65Es256VerifyProvider.Verify(_dataToSign, _composite65Es256Signature);

    [BenchmarkCategory("Verify"), Benchmark]
    public bool Verify_Composite_MLDsa87_ES384() => _composite87Es384VerifyProvider.Verify(_dataToSign, _composite87Es384Signature);
}
