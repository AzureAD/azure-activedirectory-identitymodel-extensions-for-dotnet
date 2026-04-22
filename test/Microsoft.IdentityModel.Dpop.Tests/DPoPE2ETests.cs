// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace Microsoft.IdentityModel.Dpop.Tests;

/// <summary>
/// End-to-end round-trip tests: mint access token with cnf.jkt → create proof → validate proof → verify binding.
/// </summary>
public class DPoPE2ETests
{
    private static RSA CreateTestRsa()
    {
#if NET462
        return new RSACryptoServiceProvider(2048);
#else
        return RSA.Create(2048);
#endif
    }

    /// <summary>
    /// Creates a self-signed access token with a cnf.jkt claim bound to the given key.
    /// Uses a separate signing key for the AT (simulating the AS signing key).
    /// </summary>
    private static (string AccessToken, RSA ProofKey, RSA AtSigningKey) CreateAccessTokenWithCnfJkt(
        string audience = "api://test",
        string issuer = "https://test-issuer.example.com",
        RSA proofKeyOverride = null)
    {
        var proofKey = proofKeyOverride ?? CreateTestRsa();
        var atSigningKey = CreateTestRsa();

        // Compute the JWK thumbprint of the proof key
        var proofJwk = JsonWebKeyConverter.ConvertFromSecurityKey(new RsaSecurityKey(proofKey));
        var thumbprint = DPoPProofValidator.ComputeJwkThumbprint(proofJwk);

        // Build the cnf claim
        var cnfJson = $"{{\"jkt\":\"{thumbprint}\"}}";

        // Parse cnf into JsonElement for proper embedding
        using var cnfDoc = System.Text.Json.JsonDocument.Parse(cnfJson);
        var cnfElement = cnfDoc.RootElement.Clone();

        var handler = new JsonWebTokenHandler();
        var descriptor = new SecurityTokenDescriptor
        {
            Issuer = issuer,
            Audience = audience,
            Claims = new Dictionary<string, object>
            {
                { "sub", "test-user" },
                { "cnf", cnfElement },
            },
            SigningCredentials = new SigningCredentials(new RsaSecurityKey(atSigningKey), SecurityAlgorithms.RsaSha256),
        };

        var accessToken = handler.CreateToken(descriptor);
        return (accessToken, proofKey, atSigningKey);
    }

    [Fact]
    public async Task E2E_CreateProof_ValidateProof_ValidateBinding_Succeeds()
    {
        // 1. Mint an access token with cnf.jkt bound to our proof key
        var (accessToken, proofKey, _) = CreateAccessTokenWithCnfJkt();

        // 2. Create a DPoP proof using the same key
        var proofCreator = new DPoPProofCreator(new DPoPProofCreatorOptions
        {
            SigningCredentials = new SigningCredentials(new RsaSecurityKey(proofKey), SecurityAlgorithms.RsaSha256),
        });
        var method = "GET";
        var uri = new Uri("https://api.example.com/resource");
        var proofJwt = proofCreator.CreateProof(method, uri, accessToken);

        // 3. Extract cnf.jkt from AT
        var handler = new JsonWebTokenHandler();
        var at = handler.ReadJsonWebToken(accessToken);
        Assert.True(at.TryGetPayloadValue("cnf", out System.Text.Json.JsonElement cnf));
        var jkt = cnf.GetProperty("jkt").GetString();

        // 4. Validate the proof with binding
        var validator = new DPoPProofValidator();
        var options = new DPoPValidationOptions
        {
            AllowedSigningAlgorithms = new HashSet<string>(StringComparer.Ordinal) { "RS256" },
            MaxLifetimeInSeconds = 300,
            ClockSkewInSeconds = 300,
        };

        var result = await validator.ValidateAsync(proofJwt, method, uri, accessToken, jkt, options);

        Assert.True(result.IsValid, $"Proof validation failed: {result.Error}");
    }

    [Fact]
    public async Task E2E_DifferentProofKey_BindingFails()
    {
        // AT bound to key A, proof signed by key B
        var (accessToken, _, _) = CreateAccessTokenWithCnfJkt();
        var differentKey = CreateTestRsa();

        var proofCreator = new DPoPProofCreator(new DPoPProofCreatorOptions
        {
            SigningCredentials = new SigningCredentials(new RsaSecurityKey(differentKey), SecurityAlgorithms.RsaSha256),
        });
        var method = "GET";
        var uri = new Uri("https://api.example.com/resource");
        var proofJwt = proofCreator.CreateProof(method, uri, accessToken);

        // Extract cnf.jkt from AT (bound to key A)
        var handler = new JsonWebTokenHandler();
        var at = handler.ReadJsonWebToken(accessToken);
        Assert.True(at.TryGetPayloadValue("cnf", out System.Text.Json.JsonElement cnf));
        var jkt = cnf.GetProperty("jkt").GetString();

        // Proof validates structurally but binding fails — different keys
        var validator = new DPoPProofValidator();
        var options = new DPoPValidationOptions
        {
            AllowedSigningAlgorithms = new HashSet<string>(StringComparer.Ordinal) { "RS256" },
        };
        var result = await validator.ValidateAsync(proofJwt, method, uri, accessToken, jkt, options);

        Assert.False(result.IsValid);
        Assert.Contains("cnf.jkt", result.Error);
    }

    [Fact]
    public async Task E2E_WrongAccessToken_AthMismatch()
    {
        // Create proof bound to token A, validate with token B
        var (tokenA, proofKey, _) = CreateAccessTokenWithCnfJkt();
        var (tokenB, _, _) = CreateAccessTokenWithCnfJkt(proofKeyOverride: proofKey);

        var proofCreator = new DPoPProofCreator(new DPoPProofCreatorOptions
        {
            SigningCredentials = new SigningCredentials(new RsaSecurityKey(proofKey), SecurityAlgorithms.RsaSha256),
        });
        var proofJwt = proofCreator.CreateProof("GET", new Uri("https://api.example.com/resource"), tokenA);

        // Extract cnf.jkt (same key, so jkt is the same for both tokens)
        var handler = new JsonWebTokenHandler();
        var at = handler.ReadJsonWebToken(tokenB);
        Assert.True(at.TryGetPayloadValue("cnf", out System.Text.Json.JsonElement cnf));
        var jkt = cnf.GetProperty("jkt").GetString();

        // Validate proof against token B — ath won't match
        var validator = new DPoPProofValidator();
        var options = new DPoPValidationOptions
        {
            AllowedSigningAlgorithms = new HashSet<string>(StringComparer.Ordinal) { "RS256" },
        };
        var result = await validator.ValidateAsync(
            proofJwt, "GET", new Uri("https://api.example.com/resource"), tokenB, jkt, options);

        Assert.False(result.IsValid);
        Assert.Contains("ath", result.Error);
    }

    [Fact]
    public async Task E2E_WithNonce_RoundTrip_Succeeds()
    {
        var (accessToken, proofKey, _) = CreateAccessTokenWithCnfJkt();
        var nonce = "server-provided-nonce-abc123";

        var proofCreator = new DPoPProofCreator(new DPoPProofCreatorOptions
        {
            SigningCredentials = new SigningCredentials(new RsaSecurityKey(proofKey), SecurityAlgorithms.RsaSha256),
            IncludeNonce = true,
            Nonce = nonce,
        });
        var proofJwt = proofCreator.CreateProof("POST", new Uri("https://api.example.com/data"), accessToken);

        // Extract cnf.jkt
        var handler = new JsonWebTokenHandler();
        var at = handler.ReadJsonWebToken(accessToken);
        Assert.True(at.TryGetPayloadValue("cnf", out System.Text.Json.JsonElement cnf));
        var jkt = cnf.GetProperty("jkt").GetString();

        var validator = new DPoPProofValidator();
        var options = new DPoPValidationOptions
        {
            AllowedSigningAlgorithms = new HashSet<string>(StringComparer.Ordinal) { "RS256" },
            ExpectedNonce = nonce,
        };
        var result = await validator.ValidateAsync(
            proofJwt, "POST", new Uri("https://api.example.com/data"), accessToken, jkt, options);

        Assert.True(result.IsValid, $"Proof validation with nonce failed: {result.Error}");
    }

    [Fact]
    public async Task E2E_NonceMismatch_ReturnsNonceRequired()
    {
        var (accessToken, proofKey, _) = CreateAccessTokenWithCnfJkt();

        var proofCreator = new DPoPProofCreator(new DPoPProofCreatorOptions
        {
            SigningCredentials = new SigningCredentials(new RsaSecurityKey(proofKey), SecurityAlgorithms.RsaSha256),
            IncludeNonce = true,
            Nonce = "old-nonce",
        });
        var proofJwt = proofCreator.CreateProof("GET", new Uri("https://api.example.com/resource"), accessToken);

        // Extract cnf.jkt
        var handler = new JsonWebTokenHandler();
        var at = handler.ReadJsonWebToken(accessToken);
        Assert.True(at.TryGetPayloadValue("cnf", out System.Text.Json.JsonElement cnf));
        var jkt = cnf.GetProperty("jkt").GetString();

        var validator = new DPoPProofValidator();
        var options = new DPoPValidationOptions
        {
            AllowedSigningAlgorithms = new HashSet<string>(StringComparer.Ordinal) { "RS256" },
            ExpectedNonce = "current-server-nonce",
        };
        var result = await validator.ValidateAsync(
            proofJwt, "GET", new Uri("https://api.example.com/resource"), accessToken, jkt, options);

        Assert.False(result.IsValid);
        Assert.True(result.IsNonceRequired);
    }
}