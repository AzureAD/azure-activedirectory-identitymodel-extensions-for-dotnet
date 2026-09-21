// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Security.Claims;
using System.Text.Json;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Tokens.Experimental;
using System.Collections.Generic;

#nullable enable
namespace Microsoft.IdentityModel.JsonWebTokens
{
    public partial class JsonWebTokenHandler
    {
        /// <summary>
        /// Creates a <see cref="ClaimsIdentity"/> from a <see cref="JsonWebToken"/>.
        /// </summary>
        /// <param name="jwtToken">The <see cref="JsonWebToken"/> to use as a <see cref="Claim"/> source.</param>
        /// <param name="validationParameters">The <see cref="ValidationParameters"/> to be used for validating the token.</param>
        /// <returns>A <see cref="ClaimsIdentity"/> containing the <see cref="JsonWebToken.Claims"/>.</returns>
        internal virtual ClaimsIdentity CreateClaimsIdentity(JsonWebToken? jwtToken, ValidationParameters validationParameters)
        {
            // TODO: Make protected once ValidationParameters is public.
            _ = jwtToken ?? throw LogHelper.LogArgumentNullException(nameof(jwtToken));

            return CreateClaimsIdentityPrivate(jwtToken, validationParameters, GetActualIssuer(jwtToken));
        }

        /// <summary>
        /// Creates a <see cref="ClaimsIdentity"/> from a <see cref="JsonWebToken"/> with the specified issuer.
        /// </summary>
        /// <param name="jwtToken">The <see cref="JsonWebToken"/> to use as a <see cref="Claim"/> source.</param>
        /// <param name="validationParameters">The <see cref="ValidationParameters"/> to be used for validating the token.</param>
        /// <param name="issuer">Specifies the issuer for the <see cref="ClaimsIdentity"/>.</param>
        /// <returns>A <see cref="ClaimsIdentity"/> containing the <see cref="JsonWebToken.Claims"/>.</returns>
        internal virtual ClaimsIdentity CreateClaimsIdentity(
            JsonWebToken? jwtToken,
            ValidationParameters validationParameters,
            string issuer)
        {
            // TODO: Make protected once ValidationParameters is public.
            _ = jwtToken ?? throw LogHelper.LogArgumentNullException(nameof(jwtToken));

            if (string.IsNullOrWhiteSpace(issuer))
                issuer = GetActualIssuer(jwtToken);

            if (MapInboundClaims)
                return CreateClaimsIdentityWithMapping(jwtToken, validationParameters, issuer);

            return CreateClaimsIdentityPrivate(jwtToken, validationParameters, issuer);
        }

        internal override ClaimsIdentity CreateClaimsIdentityInternal(
            SecurityToken securityToken,
            ValidationParameters validationParameters,
            string issuer)
        {
            return CreateClaimsIdentity(securityToken as JsonWebToken, validationParameters, issuer);
        }

        private ClaimsIdentity CreateClaimsIdentityWithMapping(JsonWebToken jwtToken, ValidationParameters validationParameters, string issuer)
        {
            _ = validationParameters ?? throw LogHelper.LogArgumentNullException(nameof(validationParameters));

            ClaimsIdentity identity = validationParameters.CreateClaimsIdentity(jwtToken, issuer);

            // Actor resolution is order-independent: "act" (RFC 8693 object) wins whenever present, otherwise
            // the legacy "actort" (nested-JWT string) is expanded. The raw "act"/"actort" claims are still
            // added as ordinary claims by the loop below.
            identity.Actor = ResolveActorClaimsIdentity(jwtToken, validationParameters, issuer);

            foreach (Claim jwtClaim in jwtToken.Claims)
            {
                bool wasMapped = _inboundClaimTypeMap.TryGetValue(jwtClaim.Type, out string? type);

                string claimType = type ?? jwtClaim.Type;

                if (wasMapped)
                {
                    Claim claim = new Claim(claimType, jwtClaim.Value, jwtClaim.ValueType, issuer, issuer, identity);
                    if (jwtClaim.Properties.Count > 0)
                    {
                        foreach (var kv in jwtClaim.Properties)
                        {
                            claim.Properties[kv.Key] = kv.Value;
                        }
                    }

                    claim.Properties[ShortClaimTypeProperty] = jwtClaim.Type;
                    identity.AddClaim(claim);
                }
                else
                {
                    identity.AddClaim(jwtClaim);
                }
            }

            return identity;
        }

        private ClaimsIdentity CreateClaimsIdentityPrivate(JsonWebToken jwtToken, ValidationParameters validationParameters, string issuer)
        {
            _ = validationParameters ?? throw LogHelper.LogArgumentNullException(nameof(validationParameters));

            ClaimsIdentity identity = validationParameters.CreateClaimsIdentity(jwtToken, issuer);

            // Actor resolution is order-independent: "act" (RFC 8693 object) wins whenever present, otherwise
            // the legacy "actort" (nested-JWT string) is expanded. The raw "act"/"actort" claims are still
            // added as ordinary claims by the loop below.
            identity.Actor = ResolveActorClaimsIdentity(jwtToken, validationParameters, issuer);

            foreach (Claim jwtClaim in jwtToken.Claims)
            {
                string claimType = jwtClaim.Type;

                if (jwtClaim.Properties.Count == 0)
                {
                    identity.AddClaim(new Claim(claimType, jwtClaim.Value, jwtClaim.ValueType, issuer, issuer, identity));
                }
                else
                {
                    Claim claim = new(claimType, jwtClaim.Value, jwtClaim.ValueType, issuer, issuer, identity);

                    foreach (KeyValuePair<string, string> kv in jwtClaim.Properties)
                        claim.Properties[kv.Key] = kv.Value;

                    identity.AddClaim(claim);
                }
            }

            return identity;
        }

        // Resolves ClaimsIdentity.Actor on the result-based (ValidationParameters) pipeline. The RFC 8693
        // "act" (JSON object) claim takes precedence whenever present; otherwise the legacy "actort" (an
        // unsigned nested-JWT string) is expanded for read back-compatibility. This handler only reads
        // "actort" - it never writes it. Having both "act" and "actort" is not an error: "act" wins and no
        // exception is thrown.
        private ClaimsIdentity? ResolveActorClaimsIdentity(JsonWebToken jwtToken, ValidationParameters validationParameters, string issuer)
        {
            // "act" (RFC 8693) takes precedence whenever present, in ANY form, and suppresses "actort".
            // TryGetPayloadValue<JsonElement> succeeds only for JSON objects/arrays (object -> expanded;
            // array -> the helper warns IDX14314 and yields null).
            if (jwtToken.TryGetPayloadValue<JsonElement>(ActClaimType, out JsonElement actClaim))
                return CreateActorClaimsIdentity(actClaim, validationParameters, issuer);

            // "act" present but a primitive (string/number/bool): it cannot be expanded but still wins -
            // warn IDX14314 and suppress "actort". The raw "act" value is retained as a claim by the caller.
            if (jwtToken.HasPayloadClaim(ActClaimType))
            {
                LogHelper.LogWarning(LogMessages.IDX14314);
                return null;
            }

            // Legacy fallback: "actort" is an unsigned nested JWT (not validated here, matching the classic
            // behavior). Its chain depth is not bounded by MaxActorChainLength (that bounds "act" only).
            if (jwtToken.TryGetPayloadValue<string>(JwtRegisteredClaimNames.Actort, out string actorToken)
                && CanReadToken(actorToken)
                && ReadToken(actorToken) is JsonWebToken actor)
            {
                return CreateClaimsIdentity(actor, validationParameters, GetActualIssuer(actor));
            }

            return null;
        }

        /// <summary>
        /// Creates a <see cref="ClaimsIdentity"/> from the RFC 8693 "act" (actor) claim element on the
        /// result-based (<see cref="ValidationParameters"/>) pipeline.
        /// </summary>
        /// <param name="actClaim">The "act" claim element already retrieved from the token payload.</param>
        /// <param name="validationParameters">The validation parameters.</param>
        /// <param name="issuer">The outer token's validated issuer, stamped on the actor claims.</param>
        /// <returns>
        /// A <see cref="ClaimsIdentity"/> representing the actor, or <see langword="null"/> when the "act"
        /// claim cannot be expanded into an actor identity.
        /// </returns>
        /// <exception cref="ArgumentNullException">Thrown if <paramref name="validationParameters"/> is null.</exception>
        private static ClaimsIdentity? CreateActorClaimsIdentity(
            JsonElement actClaim,
            ValidationParameters validationParameters,
            string issuer)
        {
            if (validationParameters is null)
                throw LogHelper.LogArgumentNullException(nameof(validationParameters));

            // When a custom retriever is supplied it fully owns actor construction; it is invoked
            // unconditionally (never gated by MaxActorChainLength) and its result is used as-is.
            if (validationParameters.ActClaimRetriever is not null)
            {
                try
                {
                    return validationParameters.ActClaimRetriever(actClaim, validationParameters);
                }
#pragma warning disable CA1031 // Do not catch general exception types
                catch (Exception ex)
                {
                    // A failing retriever must not fail token validation. Warn (PII-scrubbed by default) and
                    // leave Actor unset; the raw "act" claim is still retained on the identity.
                    LogHelper.LogWarning(LogMessages.IDX14313, ex);
                    return null;
                }
#pragma warning restore CA1031 // Do not catch general exception types
            }

            // Default expansion via the shared helper (bounded by MaxActorChainLength).
            return CreateActorClaimsIdentityFromJsonElement(actClaim, issuer);
        }
    }
}
#nullable restore
