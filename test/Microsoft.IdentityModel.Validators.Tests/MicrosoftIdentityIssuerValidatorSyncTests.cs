// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#if NET5_0_OR_GREATER
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Net.Http;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace Microsoft.IdentityModel.Validators.Tests
{
    public class MicrosoftIdentityIssuerValidatorSyncTests
    {
        [Fact]
        public void Validate_UsesSynchronousMetadataRetrieval()
        {
            AppContextSwitches.ResetAllSwitches();
            AppContext.SetSwitch(AppContextSwitches.PreserveLegacySyncBehaviorSwitch, false);

            try
            {
                var handler = new TrackingHttpMessageHandler();
                var validator = new AadIssuerValidator(
                    new HttpClient(handler),
                    ValidatorConstants.AuthorityCommonTenantWithV2);
                var token = new JwtSecurityToken(
                    issuer: ValidatorConstants.AadIssuer,
                    claims: [new Claim("tid", ValidatorConstants.TenantIdAsGuid)]);

                string issuer = validator.Validate(
                    ValidatorConstants.AadIssuer,
                    token,
                    new TokenValidationParameters());

                Assert.Equal(ValidatorConstants.AadIssuer, issuer);
                Assert.Equal(1, handler.SyncCalls);
                Assert.Equal(0, handler.AsyncCalls);
            }
            finally
            {
                AppContextSwitches.ResetAllSwitches();
            }
        }

        [Fact]
        public void Validate_PreserveLegacySyncBehaviorUsesAsynchronousMetadataRetrieval()
        {
            AppContextSwitches.ResetAllSwitches();
            AppContext.SetSwitch(AppContextSwitches.PreserveLegacySyncBehaviorSwitch, true);

            try
            {
                var handler = new TrackingHttpMessageHandler();
                var validator = new AadIssuerValidator(
                    new HttpClient(handler),
                    ValidatorConstants.AuthorityCommonTenantWithV2);
                var token = new JwtSecurityToken(
                    issuer: ValidatorConstants.AadIssuer,
                    claims: [new Claim("tid", ValidatorConstants.TenantIdAsGuid)]);

                string issuer = validator.Validate(
                    ValidatorConstants.AadIssuer,
                    token,
                    new TokenValidationParameters());

                Assert.Equal(ValidatorConstants.AadIssuer, issuer);
                Assert.Equal(0, handler.SyncCalls);
                Assert.Equal(1, handler.AsyncCalls);
            }
            finally
            {
                AppContextSwitches.ResetAllSwitches();
            }
        }

        [Fact]
        public async Task ValidateAsync_UsesAsynchronousMetadataRetrieval()
        {
            var handler = new TrackingHttpMessageHandler();
            var validator = new AadIssuerValidator(
                new HttpClient(handler),
                ValidatorConstants.AuthorityCommonTenantWithV2);
            var token = new JwtSecurityToken(
                issuer: ValidatorConstants.AadIssuer,
                claims: [new Claim("tid", ValidatorConstants.TenantIdAsGuid)]);

            string issuer = await validator.ValidateAsync(
                ValidatorConstants.AadIssuer,
                token,
                new TokenValidationParameters());

            Assert.Equal(ValidatorConstants.AadIssuer, issuer);
            Assert.Equal(0, handler.SyncCalls);
            Assert.Equal(1, handler.AsyncCalls);
        }

        private sealed class TrackingHttpMessageHandler : HttpMessageHandler
        {
            internal int AsyncCalls { get; private set; }

            internal int SyncCalls { get; private set; }

            protected override HttpResponseMessage Send(
                HttpRequestMessage request,
                CancellationToken cancellationToken)
            {
                SyncCalls++;
                return CreateResponse();
            }

            protected override Task<HttpResponseMessage> SendAsync(
                HttpRequestMessage request,
                CancellationToken cancellationToken)
            {
                AsyncCalls++;
                return Task.FromResult(CreateResponse());
            }

            private static HttpResponseMessage CreateResponse()
            {
                return new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent(
                        $"{{\"issuer\":\"{ValidatorConstants.AadIssuerV2CommonAuthority}\"}}")
                };
            }
        }
    }
}
#endif
