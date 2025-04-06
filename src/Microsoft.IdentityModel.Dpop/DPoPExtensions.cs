// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Buffers.Text;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Microsoft.IdentityModel.Dpop;

/// <summary>
/// Extension methods for DPoP integration.
/// </summary>
public static class DPoPExtensions
{
    /// <summary>
    /// Adds a DPoP proof to an HTTP request.
    /// </summary>
    /// <param name="request">The HTTP request message.</param>
    /// <param name="dpopProof">The DPoP proof creator.</param>
    /// <param name="accessToken">The access token to bind the proof to.</param>
    /// <param name="serverProvidedNonce">Optional server provided nonce.</param>
    /// <returns>The HTTP request with DPoP header added.</returns>
    public static HttpRequestMessage AddDPoPProof(this HttpRequestMessage request, DPoPProof dpopProof, string accessToken = null, string serverProvidedNonce = null)
    {
        if (request == null)
            throw new ArgumentNullException(nameof(request));

        if (dpopProof == null)
            throw new ArgumentNullException(nameof(dpopProof));

        string proof = dpopProof.CreateProof(request.Method.Method, request.RequestUri, accessToken, serverProvidedNonce);
        request.Headers.Add(DPoPConstants.DPoPHeaderName, proof);

        request.Headers.Authorization = new AuthenticationHeaderValue(DPoPConstants.DPoPHeaderName, accessToken);

        return request;
    }

    /// <summary>
    /// Adds a DPoP bound access token to an HTTP request.
    /// </summary>
    /// <param name="request">The HTTP request message.</param>
    /// <param name="accessToken">The access token to add.</param>
    /// <param name="dpopProof">The DPoP proof creator.</param>
    /// <param name="serverProvidedNonce">Optional server provided nonce.</param>
    /// <returns>The HTTP request with Authorization and DPoP headers added.</returns>
    public static HttpRequestMessage AddDPoPBoundAccessToken(this HttpRequestMessage request, string accessToken, DPoPProof dpopProof, string serverProvidedNonce = null)
    {
        if (request == null)
            throw new ArgumentNullException(nameof(request));

        if (string.IsNullOrEmpty(accessToken))
            throw new ArgumentNullException(nameof(accessToken));

        if (dpopProof == null)
            throw new ArgumentNullException(nameof(dpopProof));

        // Add the DPoP proof
        request.AddDPoPProof(dpopProof, accessToken, serverProvidedNonce);

        // Add the token as a DPoP bound access token
        request.Headers.Authorization = new AuthenticationHeaderValue(DPoPConstants.DPoPTokenType, accessToken);

        return request;
    }

    /// <summary>
    /// Validates whether an access token is bound to a DPoP proof.
    /// </summary>
    /// <param name="accessToken">The access token to validate.</param>
    /// <param name="dpopProof">The DPoP proof JWT.</param>
    /// <param name="options"></param>
    /// <returns>True if the token is properly bound to the proof, false otherwise.</returns>
    public static bool ValidateTokenDPoPBinding(string accessToken, string dpopProof, DPoPProofOptions options)
    {
        if (string.IsNullOrEmpty(accessToken) || string.IsNullOrEmpty(dpopProof))
            return false;

        try
        {
            // Parse the tokens
            var handler = new JsonWebTokenHandler();

            var dpopJwt = handler.ReadJsonWebToken(dpopProof);
            if (dpopJwt is null)
                return false;

            var accessJwt = handler.ReadJsonWebToken(accessToken);
            if (accessJwt is null)
                return false;

            // Extract the JWK from DPoP proof
            if (!dpopJwt.TryGetPayloadValue("jwk", out string jwkObj) || jwkObj is null)
                return false;

            // Convert the JWK object to a JsonWebKey
            JsonWebKey jwk = new(jwkObj);

            // Calculate thumbprint for binding validation, need the sha-256 hash, but also base64url encoded.
            ReadOnlySpan<byte> publicJwk = JsonWebKeyConverter.ConvertFromSecurityKey(options.SigningCredentials.Key).ComputeJwkThumbprint();
            var thumbprint = Base64Url.EncodeToString(publicJwk);

            // Check if the access token has the confirmation claim
            if (accessJwt.TryGetPayloadValue(DPoPConstants.ConfirmationClaimType, out string cnfObj) && !string.IsNullOrEmpty(cnfObj))
            {
                var cnf = new Cnf(cnfObj);
                if (cnf.Jku == thumbprint)
                    return true;
            }

            return false;
        }
        catch
        {
            return false;
        }
    }
}
