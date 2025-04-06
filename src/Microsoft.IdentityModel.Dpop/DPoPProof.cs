// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using System.Threading.Tasks;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Microsoft.IdentityModel.Dpop;

/// <summary>
/// This class creates and validates DPoP proof JWTs according to RFC 9449.
/// </summary>
public class DPoPProof
{
    private readonly DPoPProofOptions _options;

    /// <summary>
    /// Initializes a new instance of the <see cref="DPoPProof"/> class.
    /// </summary>
    /// <param name="options">The options for creating and validating DPoP proofs.</param>
    public DPoPProof(DPoPProofOptions options)
    {
        _options = options ?? throw new ArgumentNullException(nameof(options));

        if (_options.SigningCredentials == null)
            throw new ArgumentException("SigningCredentials must be provided", nameof(options));
    }

    /// <summary>
    /// Creates a DPoP proof JWT for the specified HTTP request.
    /// </summary>
    /// <param name="httpMethod">The HTTP method of the request.</param>
    /// <param name="uri">The URI of the request.</param>
    /// <param name="accessToken">The access token to bind this proof to.</param>
    /// <param name="serverProvidedNonce">Optional server provided nonce to include in the proof.</param>
    /// <returns>A JWT string representing the DPoP proof.</returns>
    public string CreateProof(string httpMethod, Uri uri, string accessToken = null, string serverProvidedNonce = null)
    {
        if (string.IsNullOrEmpty(httpMethod))
            throw new ArgumentNullException(nameof(httpMethod));

        if (uri is null)
            throw new ArgumentNullException(nameof(uri));

        var now = _options.TimeProvider.GetUtcNow();

        var claims = new Dictionary<string, object>
        {
            // DPoP RFC 9449 required claims
            { "htm", httpMethod.ToUpperInvariant() },
            { "htu", uri.GetLeftPart(UriPartial.Path) },
            { "iat", now.ToUnixTimeSeconds() },
            { "jti", Guid.NewGuid().ToString() }
        };

        if (!string.IsNullOrEmpty(accessToken))
        {
            var tokenBytes = Encoding.UTF8.GetBytes(accessToken);
            var tokenHash = SHA256.HashData(tokenBytes);
            var tokenHashBase64 = Base64UrlEncoder.Encode(tokenHash);
            claims.Add("ath", tokenHashBase64);
        }

        // Include a nonce if specified in options or provided by server
        if (_options.IncludeNonce || !string.IsNullOrEmpty(serverProvidedNonce))
        {
            string nonceValue = serverProvidedNonce ??
                _options.Nonce ?? Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
            claims.Add("nonce", nonceValue);
        }

        JsonObject jwk = JsonWebKeyConverter.ConvertFromSecurityKey(_options.SigningCredentials.Key).RepresentAsAsymmetricPublicJwkForDpop();

        var headerClaims = new Dictionary<string, object>
        {
            { "typ", "dpop+jwt" },
            { "jwk", jwk }
        };

        var tokenDescriptor = new SecurityTokenDescriptor
        {
            IncludeKeyIdInHeader = false,
            Claims = claims,
            AdditionalHeaderClaims = headerClaims,
            SigningCredentials = _options.SigningCredentials,
        };

        var handler = new JsonWebTokenHandler()
        {
            SetDefaultTimesOnTokenCreation = false,
        };

        var token = handler.CreateToken(tokenDescriptor);

        return token;
    }

    /// <summary>
    /// Validates a DPoP proof JWT against the specified HTTP request.
    /// </summary>
    /// <param name="proofToken">The DPoP proof JWT to validate.</param>
    /// <param name="httpMethod">The HTTP method of the request.</param>
    /// <param name="uri">The URI of the request.</param>
    /// <param name="expectedNonce">Optional expected nonce value.</param>
    /// <returns>A validation result indicating if the proof is valid.</returns>
    public async Task<DPoPValidationResult> ValidateProofAsync(string proofToken, string httpMethod, Uri uri, string expectedNonce = null)
    {
        if (string.IsNullOrEmpty(proofToken))
            return new DPoPValidationResult { IsValid = false, Error = "DPoP proof is null or empty" };

        if (string.IsNullOrEmpty(httpMethod))
            return new DPoPValidationResult { IsValid = false, Error = "HTTP method is null or empty" };

        if (uri == null)
            return new DPoPValidationResult { IsValid = false, Error = "URI is null" };

        var handler = new JsonWebTokenHandler();

        TokenValidationParameters validationParameters = _options.ValidationParameters?.Clone();
        if (validationParameters == null)
        {
            validationParameters = new TokenValidationParameters
            {
                ValidateIssuer = false,
                ValidateAudience = false,
                ValidateLifetime = false,
                IssuerSigningKey = _options.SigningCredentials.Key
            };
        }

        try
        {
            var jsonToken = handler.ReadJsonWebToken(proofToken);
            var result = await handler.ValidateTokenAsync(jsonToken, validationParameters).ConfigureAwait(false);
            if (!result.IsValid)
                return new DPoPValidationResult { IsValid = false, Error = "Invalid token signature or format" };

            var token = result.SecurityToken as JsonWebToken;
            if (token == null)
                return new DPoPValidationResult { IsValid = false, Error = "Token could not be parsed as JsonWebToken" };

            // Validate required claims
            if (!token.TryGetPayloadValue("htm", out string htmValue) ||
                !httpMethod.Equals(htmValue, StringComparison.OrdinalIgnoreCase))
                return new DPoPValidationResult { IsValid = false, Error = "htm claim missing or doesn't match HTTP method" };

            if (!token.TryGetPayloadValue("htu", out string htuValue) ||
                !uri.GetLeftPart(UriPartial.Path).Equals(htuValue, StringComparison.OrdinalIgnoreCase))
                return new DPoPValidationResult { IsValid = false, Error = "htu claim missing or doesn't match HTTP URI" };

            if (!token.TryGetPayloadValue("iat", out long iat))
                return new DPoPValidationResult { IsValid = false, Error = "iat claim is missing" };

            // Check timestamp freshness
            var issuedAt = EpochTime.DateTime(iat);
            var now = _options.TimeProvider.GetUtcNow();
            if (issuedAt.Add(TimeSpan.FromSeconds(_options.MaxProofAgeInSeconds)) < now)
                return new DPoPValidationResult { IsValid = false, Error = "DPoP proof has expired" };

            // Check for JWK
            if (!token.TryGetHeaderValue("jwk", out string jwk) || jwk == null)
                return new DPoPValidationResult { IsValid = false, Error = "jwk claim is missing" };

            // Check nonce if expected
            if (!string.IsNullOrEmpty(expectedNonce))
            {
                if (!token.TryGetPayloadValue("nonce", out string nonce) || !expectedNonce.Equals(nonce, StringComparison.Ordinal))
                    return new DPoPValidationResult { IsValid = false, Error = "nonce claim missing or doesn't match expected value" };
            }

            return new DPoPValidationResult { IsValid = true };
        }
#pragma warning disable CA1031 // Do not catch general exception types
        catch (Exception ex)
        {
            return new DPoPValidationResult { IsValid = false, Error = $"Exception validating DPoP proof: {ex.Message}" };
        }
#pragma warning restore CA1031 // Do not catch general exception types
    }
}

/// <summary>
/// Represents the result of validating a DPoP proof.
/// </summary>
public class DPoPValidationResult
{
    /// <summary>
    /// Gets or sets a value indicating whether the DPoP proof is valid.
    /// </summary>
    public bool IsValid { get; set; }

    /// <summary>
    /// Gets or sets an error message if the proof is invalid.
    /// </summary>
    public string Error { get; set; }
}
