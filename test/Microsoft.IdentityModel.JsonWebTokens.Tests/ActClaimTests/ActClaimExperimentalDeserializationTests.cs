// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Diagnostics.Tracing;
using System.Linq;
using System.Security.Claims;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.IdentityModel.TestUtils;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Tokens.Experimental;
using Xunit;

namespace Microsoft.IdentityModel.JsonWebTokens.Tests.ActClaimTests
{
    /// <summary>
    /// Deserialization of the RFC 8693 "act" claim into <see cref="ClaimsIdentity.Actor"/> on the
    /// result-based (<see cref="ValidationParameters"/>) validation pipeline - the companion of the
    /// <see cref="ActClaimDeserializationTests"/> which cover the legacy TokenValidationParameters pipeline.
    /// </summary>
    [Collection("ActClaimTests")]
    public class ActClaimExperimentalDeserializationTests : IDisposable
    {
        // Reset the process-wide MaxActorChainLength after every test for isolation.
        public void Dispose() => JsonWebTokenHandler.MaxActorChainLength = 1;

        private static ValidationParameters ValidationParameters =>
            ValidationUtils.CreateValidationParameters(
                audiences: [Default.Audience],
                issuers: [Default.Issuer],
                signingKeys: [Default.AsymmetricSigningKey]);

        private static string CreateTokenWithClaims(ClaimsIdentity subject, IDictionary<string, object> extraClaims = null)
        {
            var descriptor = new SecurityTokenDescriptor
            {
                Subject = subject,
                Issuer = Default.Issuer,
                Audience = Default.Audience,
                IssuedAt = DateTime.UtcNow.AddMinutes(-5),
                NotBefore = DateTime.UtcNow.AddMinutes(-5),
                Expires = DateTime.UtcNow.AddHours(1),
                SigningCredentials = Default.AsymmetricSigningCredentials,
            };

            if (extraClaims is not null)
                descriptor.Claims = extraClaims;

            return new JsonWebTokenHandler().CreateToken(descriptor);
        }

        private static async Task<ValidationResult<ValidatedToken, ValidationError>> ValidateAsync(
            string token, ValidationParameters validationParameters) =>
            await ((IResultBasedValidation)new JsonWebTokenHandler())
                .ValidateTokenAsync(token, validationParameters, new CallContext(), CancellationToken.None);

        [Fact]
        public async Task ValidateTokenAsync_ActObject_PopulatesActorFromAct()
        {
            // Arrange - an "act" (RFC 8693 JSON object) actor on the outgoing token.
            var actor = new CaseSensitiveClaimsIdentity("ActorAuth");
            actor.AddClaim(new Claim("sub", "actor-subject-id"));
            actor.AddClaim(new Claim("name", "Actor Name"));

            var main = new CaseSensitiveClaimsIdentity("Bearer");
            main.AddClaim(new Claim("sub", "main-subject-id"));

            string token = CreateTokenWithClaims(main, new Dictionary<string, object> { { "act", actor } });

            // Act
            ValidationResult<ValidatedToken, ValidationError> result = await ValidateAsync(token, ValidationParameters);

            // Assert
            Assert.True(result.Succeeded);
            ClaimsIdentity actorIdentity = result.Result.ClaimsIdentity.Actor;
            Assert.NotNull(actorIdentity);
            Assert.Equal("actor-subject-id", actorIdentity.Claims.First(c => c.Type == "sub").Value);
            Assert.Equal("Actor Name", actorIdentity.Claims.First(c => c.Type == "name").Value);
        }

        [Fact]
        public async Task ValidateTokenAsync_NestedAct_ExpandsWithinMaxActorChainLength()
        {
            // Arrange - two actor levels require a chain length of 2.
            JsonWebTokenHandler.MaxActorChainLength = 2;

            var nested = new CaseSensitiveClaimsIdentity("NestedActorAuth");
            nested.AddClaim(new Claim("sub", "nested-actor-id"));

            var actor = new CaseSensitiveClaimsIdentity("ActorAuth");
            actor.AddClaim(new Claim("sub", "actor-subject-id"));
            actor.Actor = nested;

            var main = new CaseSensitiveClaimsIdentity("Bearer");
            main.AddClaim(new Claim("sub", "main-subject-id"));

            string token = CreateTokenWithClaims(main, new Dictionary<string, object> { { "act", actor } });

            // Act
            ValidationResult<ValidatedToken, ValidationError> result = await ValidateAsync(token, ValidationParameters);

            // Assert
            Assert.True(result.Succeeded);
            ClaimsIdentity actorIdentity = result.Result.ClaimsIdentity.Actor;
            Assert.NotNull(actorIdentity);
            Assert.Equal("actor-subject-id", actorIdentity.Claims.First(c => c.Type == "sub").Value);
            Assert.NotNull(actorIdentity.Actor);
            Assert.Equal("nested-actor-id", actorIdentity.Actor.Claims.First(c => c.Type == "sub").Value);
        }

        [Fact]
        public async Task ValidateTokenAsync_CustomActClaimRetriever_OwnsActorConstruction()
        {
            // Arrange - a custom retriever fully owns actor construction from the raw JsonElement.
            static ClaimsIdentity CustomRetriever(JsonElement element, ValidationParameters validationParameters)
            {
                var id = new CaseSensitiveClaimsIdentity("CustomActorAuth");
                if (element.TryGetProperty("sub", out JsonElement sub))
                    id.AddClaim(new Claim("sub", sub.GetString()));
                return id;
            }

            var actor = new CaseSensitiveClaimsIdentity("ActorAuth");
            actor.AddClaim(new Claim("sub", "actor-subject-id"));

            var main = new CaseSensitiveClaimsIdentity("Bearer");
            main.AddClaim(new Claim("sub", "main-subject-id"));

            string token = CreateTokenWithClaims(main, new Dictionary<string, object> { { "act", actor } });

            ValidationParameters validationParameters = ValidationParameters;
            validationParameters.ActClaimRetriever = CustomRetriever;

            // Act
            ValidationResult<ValidatedToken, ValidationError> result = await ValidateAsync(token, validationParameters);

            // Assert
            Assert.True(result.Succeeded);
            ClaimsIdentity actorIdentity = result.Result.ClaimsIdentity.Actor;
            Assert.NotNull(actorIdentity);
            Assert.Equal("CustomActorAuth", actorIdentity.AuthenticationType);
            Assert.Equal("actor-subject-id", actorIdentity.Claims.First(c => c.Type == "sub").Value);
        }

        [Fact]
        public async Task ValidateTokenAsync_FailingActClaimRetriever_WarnsAndLeavesActorNull()
        {
            // Arrange - a failing ActClaimRetriever must NOT fail token validation. It warns (IDX14313) and
            // leaves Actor null; the raw "act" claim is still retained.
            using var listener = SampleListener.CreateLoggerListener(EventLevel.Warning);

            static ClaimsIdentity ThrowingRetriever(JsonElement element, ValidationParameters validationParameters) =>
                throw new InvalidOperationException("retriever failure");

            var actor = new CaseSensitiveClaimsIdentity("ActorAuth");
            actor.AddClaim(new Claim("sub", "actor-subject-id"));

            var main = new CaseSensitiveClaimsIdentity("Bearer");
            main.AddClaim(new Claim("sub", "main-subject-id"));

            string token = CreateTokenWithClaims(main, new Dictionary<string, object> { { "act", actor } });

            ValidationParameters validationParameters = ValidationParameters;
            validationParameters.ActClaimRetriever = ThrowingRetriever;

            // Act
            ValidationResult<ValidatedToken, ValidationError> result = await ValidateAsync(token, validationParameters);

            // Assert - validation succeeds and the identity is accessible without throwing.
            Assert.True(result.Succeeded);
            ClaimsIdentity identity = result.Result.ClaimsIdentity;
            Assert.Null(identity.Actor);
            Assert.Contains(identity.Claims, c => c.Type == "act");
            Assert.Contains("IDX14313", listener.TraceBuffer);
        }

        [Fact]
        public async Task ValidateTokenAsync_PrimitiveAct_WarnsAndRetainsClaimWithoutActor()
        {
            // Arrange - a non-object "act" (a primitive) cannot be expanded; it warns (IDX14314), leaves
            // Actor null, and is kept as an ordinary claim, and it still suppresses any legacy "actort".
            using var listener = SampleListener.CreateLoggerListener(EventLevel.Warning);

            var main = new CaseSensitiveClaimsIdentity("Bearer");
            main.AddClaim(new Claim("sub", "main-subject-id"));

            string token = CreateTokenWithClaims(main, new Dictionary<string, object> { { "act", "not-an-object" } });

            // Act
            ValidationResult<ValidatedToken, ValidationError> result = await ValidateAsync(token, ValidationParameters);

            // Assert
            Assert.True(result.Succeeded);
            Assert.Null(result.Result.ClaimsIdentity.Actor);
            Assert.Contains("IDX14314", listener.TraceBuffer);
            Assert.Contains(result.Result.ClaimsIdentity.Claims, c => c.Type == "act" && c.Value == "not-an-object");
        }

        [Fact]
        public async Task ValidateTokenAsync_WithBothActAndActort_OnlyActIsExpanded()
        {
            // Arrange - build a legacy "actort" JWT string with a distinguishable actor subject.
            var actortActor = new CaseSensitiveClaimsIdentity("ActortAuth");
            actortActor.AddClaim(new Claim("sub", "actort-actor-id"));
            string actortJwt = new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
            {
                Subject = actortActor,
                Issuer = Default.Issuer,
                Audience = Default.Audience,
                SigningCredentials = Default.AsymmetricSigningCredentials,
            });

            var actActor = new CaseSensitiveClaimsIdentity("ActAuth");
            actActor.AddClaim(new Claim("sub", "act-actor-id"));

            var main = new CaseSensitiveClaimsIdentity("Bearer");
            main.AddClaim(new Claim("sub", "main-subject-id"));

            string token = CreateTokenWithClaims(main, new Dictionary<string, object>
            {
                { "act", actActor },
                { "actort", actortJwt }
            });

            // Act
            ValidationResult<ValidatedToken, ValidationError> result = await ValidateAsync(token, ValidationParameters);

            // Assert - only "act" (JSON object) is expanded into Actor; "actort" is retained as a string claim.
            Assert.True(result.Succeeded);
            ClaimsIdentity actorIdentity = result.Result.ClaimsIdentity.Actor;
            Assert.NotNull(actorIdentity);
            Assert.Equal("act-actor-id", actorIdentity.Claims.First(c => c.Type == "sub").Value);
            Assert.DoesNotContain(actorIdentity.Claims, c => c.Value == "actort-actor-id");
            Assert.Contains(result.Result.ClaimsIdentity.Claims, c => c.Type == "actort" && c.Value == actortJwt);
        }

        [Fact]
        public async Task ValidateTokenAsync_MapInboundClaimsTrue_PopulatesActorFromAct()
        {
            // Arrange - the MapInboundClaims path must also resolve "act" into Actor (detected via the raw
            // "act" type, so inbound claim mapping cannot hide it).
            var actor = new CaseSensitiveClaimsIdentity("ActorAuth");
            actor.AddClaim(new Claim("sub", "actor-subject-id"));

            var main = new CaseSensitiveClaimsIdentity("Bearer");
            main.AddClaim(new Claim("sub", "main-subject-id"));

            string token = CreateTokenWithClaims(main, new Dictionary<string, object> { { "act", actor } });

            var handler = new JsonWebTokenHandler { MapInboundClaims = true };

            // Act
            ValidationResult<ValidatedToken, ValidationError> result = await ((IResultBasedValidation)handler)
                .ValidateTokenAsync(token, ValidationParameters, new CallContext(), CancellationToken.None);

            // Assert
            Assert.True(result.Succeeded);
            ClaimsIdentity actorIdentity = result.Result.ClaimsIdentity.Actor;
            Assert.NotNull(actorIdentity);
            Assert.Equal("actor-subject-id", actorIdentity.Claims.First(c => c.Type == "sub").Value);
        }
    }
}
