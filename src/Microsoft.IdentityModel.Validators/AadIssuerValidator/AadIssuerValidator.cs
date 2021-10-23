//------------------------------------------------------------------------------
//
// Copyright (c) Microsoft Corporation.
// All rights reserved.
//
// This code is licensed under the MIT License.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files(the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and / or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions :
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
//
//------------------------------------------------------------------------------

using System;
using System.IdentityModel.Tokens.Jwt;
using System.Net.Http;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Tokens;

namespace Microsoft.IdentityModel.Validators
{
    /// <summary>
    /// Generic class that validates either JsonWebTokens or JwtSecurityTokens issued from the Microsoft identity platform (AAD).
    /// </summary>
    public class AadIssuerValidator
    {
        internal AadIssuerValidator(
            HttpClient httpClient,
            string aadAuthority)
        {
            HttpClient = httpClient;
            AadAuthority = aadAuthority.TrimEnd('/');
        }

        private HttpClient HttpClient { get; }
        internal string AadIssuerV1 { get; set; }
        internal string AadIssuerV2 { get; set; }
        internal string AadAuthority { get; set; }

        /// <summary>
        /// Validate the issuer for single and multi-tenant applications of various audiences (Work and School accounts, or Work and School accounts +
        /// Personal accounts) and the various clouds.
        /// </summary>
        /// <param name="issuer">Issuer to validate (will be tenanted).</param>
        /// <param name="securityToken">Received security token.</param>
        /// <param name="validationParameters">Token validation parameters.</param>
        /// <example><code>
        /// AadIssuerValidatorFactory factory = new AadIssuerValidatorFactory();
        /// TokenValidationParameters.IssuerValidator = factory.GetAadIssuerValidator(authority).Validate;
        /// </code></example>
        /// <remarks>The issuer is considered as valid if it has the same HTTP scheme and authority as the
        /// authority from the configuration file, has a tenant ID, and optionally v2.0 (this web API
        /// accepts both V1 and V2 tokens).</remarks>
        /// <returns>The <c>issuer</c> if it's valid, or otherwise <c>SecurityTokenInvalidIssuerException</c> is thrown.</returns>
        /// <exception cref="ArgumentNullException"> if <paramref name="securityToken"/> is null.</exception>
        /// <exception cref="ArgumentNullException"> if <paramref name="validationParameters"/> is null.</exception>
        /// <exception cref="SecurityTokenInvalidIssuerException">if the issuer is invalid or if there is a network issue. </exception>
        public string Validate(
            string issuer,
            SecurityToken securityToken,
            TokenValidationParameters validationParameters)
        {
            _ = issuer ?? throw new ArgumentNullException(nameof(issuer));
            _ = securityToken ?? throw new ArgumentNullException(nameof(securityToken));
            _ = validationParameters ?? throw new ArgumentNullException(nameof(validationParameters));

            string tenantId = GetTenantIdFromToken(securityToken);

            if (string.IsNullOrWhiteSpace(tenantId))
                throw LogHelper.LogExceptionMessage(new SecurityTokenInvalidIssuerException(LogMessages.IDX40105));

            if (validationParameters.ValidIssuers != null)
            {
                foreach (var validIssuerTemplate in validationParameters.ValidIssuers)
                {
                    if (IsValidIssuer(validIssuerTemplate, tenantId, issuer))
                        return issuer;
                }
            }

            if (validationParameters.ValidIssuer != null)
            {
                if (IsValidIssuer(validationParameters.ValidIssuer, tenantId, issuer))
                    return issuer;
            }

            try
            {
                if (securityToken.Issuer.EndsWith("v2.0", StringComparison.OrdinalIgnoreCase))
                {
                    if (AadIssuerV2 == null)
                    {
                        IssuerMetadata issuerMetadata =
                            CreateConfigManager(AadAuthority).GetConfigurationAsync().ConfigureAwait(false).GetAwaiter().GetResult();
                        AadIssuerV2 = issuerMetadata.Issuer;
                    }

                    if (IsValidIssuer(AadIssuerV2, tenantId, issuer))
                        return issuer;
                }
                else
                {
                    if (AadIssuerV1 == null)
                    {
                        IssuerMetadata issuerMetadata =
                            CreateConfigManager(CreateV1Authority()).GetConfigurationAsync().ConfigureAwait(false).GetAwaiter().GetResult();
                        AadIssuerV1 = issuerMetadata.Issuer;
                    }

                    if (IsValidIssuer(AadIssuerV1, tenantId, issuer))
                        return issuer;
                }
            }
            catch (Exception ex)
            {
                throw LogHelper.LogExceptionMessage(new SecurityTokenInvalidIssuerException(LogHelper.FormatInvariant(LogMessages.IDX40103, issuer), ex));
            }

            // If a valid issuer is not found, throw
            throw LogHelper.LogExceptionMessage(new SecurityTokenInvalidIssuerException(LogHelper.FormatInvariant(LogMessages.IDX40103, issuer)));
        }

        private string CreateV1Authority()
        {
            if (AadAuthority.Contains(AadIssuerValidatorConstants.Organizations))
                return AadAuthority.Replace($"{AadIssuerValidatorConstants.Organizations}/v2.0", AadIssuerValidatorConstants.Common);

            return AadAuthority.Replace("/v2.0", string.Empty);
        }

        private ConfigurationManager<IssuerMetadata> CreateConfigManager(
            string aadAuthority)
        {
            if (HttpClient != null)
            {
                return
                 new ConfigurationManager<IssuerMetadata>(
                     $"{aadAuthority}{AadIssuerValidatorConstants.OidcEndpoint}",
                     new IssuerConfigurationRetriever(),
                     HttpClient);
            }
            else
            {
                return
                new ConfigurationManager<IssuerMetadata>(
                    $"{aadAuthority}{AadIssuerValidatorConstants.OidcEndpoint}",
                    new IssuerConfigurationRetriever());
            }
        }

        private static bool IsValidIssuer(string validIssuerTemplate, string tenantId, string actualIssuer)
        {
            if (string.IsNullOrEmpty(validIssuerTemplate))
                return false;

            if (validIssuerTemplate.Contains("{tenantid}"))
            {
                try
                {
                    Uri issuerFromTemplateUri = new Uri(validIssuerTemplate.Replace("{tenantid}", tenantId));

                    Uri actualIssuerUri = new Uri(actualIssuer);

                    return issuerFromTemplateUri.AbsoluteUri == actualIssuerUri.AbsoluteUri;
                }
#pragma warning disable CA1031 // Do not catch general exception types
                catch
#pragma warning restore CA1031 // Do not catch general exception types
                {
                    // if something faults, ignore
                }

                return false;
            }
            else
            {
                return validIssuerTemplate == actualIssuer;
            }
        }

        /// <summary>Gets the tenant ID from a token.</summary>
        /// <param name="securityToken">A JWT token.</param>
        /// <returns>A string containing the tenant ID, if found or <see cref="string.Empty"/>.</returns>
        /// <remarks>Only <see cref="JwtSecurityToken"/> and <see cref="JsonWebToken"/> are acceptable types.</remarks>
        private static string GetTenantIdFromToken(SecurityToken securityToken)
        {
            if (securityToken is JwtSecurityToken jwtSecurityToken)
            {
                if (jwtSecurityToken.Payload.TryGetValue(AadIssuerValidatorConstants.Tid, out object tid))
                    return (string)tid;

                jwtSecurityToken.Payload.TryGetValue(AadIssuerValidatorConstants.TenantId, out object tenantId);
                if (tenantId != null)
                    return (string)tenantId;

                // Since B2C doesn't have "tid" as default, get it from issuer
                return GetTenantIdFromIss(jwtSecurityToken.Issuer);
            }

            if (securityToken is JsonWebToken jsonWebToken)
            {
                jsonWebToken.TryGetPayloadValue(AadIssuerValidatorConstants.Tid, out string tid);
                if (tid != null)
                    return tid;

                jsonWebToken.TryGetPayloadValue(AadIssuerValidatorConstants.TenantId, out string tenantId);
                if (tenantId != null)
                    return tenantId;

                // Since B2C doesn't have "tid" as default, get it from issuer
                return GetTenantIdFromIss(jsonWebToken.Issuer);
            }

            return string.Empty;
        }

        // The AAD "iss" claims contains the tenant ID in its value.
        // The URI can be
        // - {domain}/{tid}/v2.0
        // - {domain}/{tid}/v2.0/
        // - {domain}/{tfp}/{tid}/{userFlow}/v2.0/
        private static string GetTenantIdFromIss(string iss)
        {
            if (string.IsNullOrEmpty(iss))
                return string.Empty;

            var uri = new Uri(iss);

            if (uri.Segments.Length == 3)
                return uri.Segments[1].TrimEnd('/');

            if (uri.Segments.Length == 5 && uri.Segments[1].TrimEnd('/') == AadIssuerValidatorConstants.Tfp)
                throw new SecurityTokenInvalidIssuerException(LogMessages.IDX40104);

            return string.Empty;
        }
    }
}
