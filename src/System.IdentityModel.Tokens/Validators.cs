//-----------------------------------------------------------------------
// Copyright (c) Microsoft Open Technologies, Inc.
// All Rights Reserved
// Apache License 2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// 
// http://www.apache.org/licenses/LICENSE-2.0
// 
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//-----------------------------------------------------------------------

using System.Collections.Generic;
using System.Diagnostics.Tracing;
using System.Globalization;
using Microsoft.IdentityModel.Logging;

namespace System.IdentityModel.Tokens
{
    /// <summary>
    /// AudienceValidator
    /// </summary>
    public static class Validators
    {
        /// <summary>
        /// Determines if the audiences found in a <see cref="SecurityToken"/> are valid.
        /// </summary>
        /// <param name="audiences">The audiences found in the <see cref="SecurityToken"/>.</param>
        /// <param name="securityToken">The <see cref="SecurityToken"/> being validated.</param>
        /// <param name="validationParameters"><see cref="TokenValidationParameters"/> required for validation.</param>
        /// <exception cref="ArgumentNullException"> if 'vaidationParameters' is null.</exception>
        /// <exception cref="ArgumentNullException"> if 'audiences' is null and <see cref="TokenValidationParameters.ValidateAudience"/> is true.</exception>
        /// <exception cref="SecurityTokenInvalidAudienceException"> if <see cref="TokenValidationParameters.ValidAudience"/> is null or whitespace and <see cref="TokenValidationParameters.ValidAudiences"/> is null.</exception>
        /// <exception cref="SecurityTokenInvalidAudienceException"> if none of the 'audiences' matched either <see cref="TokenValidationParameters.ValidAudience"/> or one of <see cref="TokenValidationParameters.ValidAudiences"/>.</exception>
        /// <remarks>An EXACT match is required.</remarks>
        public static void ValidateAudience(IEnumerable<string> audiences, SecurityToken securityToken, TokenValidationParameters validationParameters)
        {
            if(validationParameters == null)
            {
                LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, ErrorMessages.IDX10000, "validationParameters"), typeof(ArgumentNullException), EventLevel.Verbose);
            }

            if (!validationParameters.ValidateAudience)
            {
                IdentityModelEventSource.Logger.WriteWarning("ValidateAudience property on ValidationParamaters is set to false. Exiting without validating the audience.");
                return;
            }

            if (audiences == null)
            {
                LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, ErrorMessages.IDX10214, Utility.SerializeAsSingleCommaDelimitedString(audiences), validationParameters.ValidAudience ?? "null", Utility.SerializeAsSingleCommaDelimitedString(validationParameters.ValidAudiences)), typeof(SecurityTokenInvalidAudienceException), EventLevel.Error);
            }

            if (string.IsNullOrWhiteSpace(validationParameters.ValidAudience) && (validationParameters.ValidAudiences == null))
            {
                LogHelper.Throw(ErrorMessages.IDX10208, typeof(SecurityTokenInvalidAudienceException), EventLevel.Error);
            }

            foreach (string audience in audiences)
            {
                if (string.IsNullOrWhiteSpace(audience))
                {
                    continue;
                }

                if (validationParameters.ValidAudiences != null)
                {
                    foreach (string str in validationParameters.ValidAudiences)
                    {
                        if (string.Equals(audience, str, StringComparison.Ordinal))
                        {
                            IdentityModelEventSource.Logger.WriteInformation(string.Format(CultureInfo.InvariantCulture, "Audience Validated. Audience: {0}", audience));
                            return;
                        }
                    }
                }

                if (!string.IsNullOrWhiteSpace(validationParameters.ValidAudience))
                {
                    if (string.Equals(audience, validationParameters.ValidAudience, StringComparison.Ordinal))
                    {
                        IdentityModelEventSource.Logger.WriteInformation(string.Format(CultureInfo.InvariantCulture, "Audience Validated. Audience: {0}", audience));
                        return;
                    }
                }
            }

            LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, ErrorMessages.IDX10214, Utility.SerializeAsSingleCommaDelimitedString(audiences), validationParameters.ValidAudience ?? "null", Utility.SerializeAsSingleCommaDelimitedString(validationParameters.ValidAudiences)), typeof(SecurityTokenInvalidAudienceException), EventLevel.Error);
        }
    
        /// <summary>
        /// Determines if an issuer found in a <see cref="SecurityToken"/> is valid.
        /// </summary>
        /// <param name="issuer">The issuer to validate</param>
        /// <param name="securityToken">The <see cref="SecurityToken"/> that is being validated.</param>
        /// <param name="validationParameters"><see cref="TokenValidationParameters"/> required for validation.</param>
        /// <returns>The issuer to use when creating the "Claim"(s) in a "ClaimsIdentity".</returns>
        /// <exception cref="ArgumentNullException"> if 'vaidationParameters' is null.</exception>
        /// <exception cref="ArgumentNullException"> if 'issuer' is null or whitespace and <see cref="TokenValidationParameters.ValidateIssuer"/> is true.</exception>
        /// <exception cref="SecurityTokenInvalidIssuerException"> if <see cref="TokenValidationParameters.ValidIssuer"/> is null or whitespace and <see cref="TokenValidationParameters.ValidIssuers"/> is null.</exception>
        /// <exception cref="SecurityTokenInvalidIssuerException"> if 'issuer' failed to matched either <see cref="TokenValidationParameters.ValidIssuer"/> or one of <see cref="TokenValidationParameters.ValidIssuers"/>.</exception>
        /// <remarks>An EXACT match is required.</remarks>
        public static string ValidateIssuer(string issuer, SecurityToken securityToken, TokenValidationParameters validationParameters)
        {
            if (validationParameters == null)
            {
                LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, ErrorMessages.IDX10000, "validationParameters"), typeof(ArgumentNullException), EventLevel.Verbose);
            }

            if (!validationParameters.ValidateIssuer)
            {
                IdentityModelEventSource.Logger.WriteInformation("ValidateIssuer property on ValidationParamaters is set to false. Exiting without validating the issuer.");
                return issuer;
            }

            if (string.IsNullOrWhiteSpace(issuer))
            {
                LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, ErrorMessages.IDX10211), typeof(SecurityTokenInvalidIssuerException), EventLevel.Error);
            }

            // Throw if all possible places to validate against are null or empty
            if (string.IsNullOrWhiteSpace(validationParameters.ValidIssuer) && (validationParameters.ValidIssuers == null))
            {
                LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, ErrorMessages.IDX10204), typeof(SecurityTokenInvalidIssuerException), EventLevel.Error);

            }

            if (string.Equals(validationParameters.ValidIssuer, issuer, StringComparison.Ordinal))
            {
                IdentityModelEventSource.Logger.WriteInformation(string.Format(CultureInfo.InvariantCulture, "Issuer Validated. Issuer: {0}", issuer));
                return issuer;
            }

            if (null != validationParameters.ValidIssuers)
            {
                foreach (string str in validationParameters.ValidIssuers)
                {
                    if (string.Equals(str, issuer, StringComparison.Ordinal))
                    {
                        IdentityModelEventSource.Logger.WriteInformation(string.Format(CultureInfo.InvariantCulture, "Issuer Validated. Issuer: {0}", issuer));
                        return issuer;
                    }
                }
            }

            LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, ErrorMessages.IDX10205, issuer, validationParameters.ValidIssuer ?? "null", Utility.SerializeAsSingleCommaDelimitedString(validationParameters.ValidIssuers)),typeof(SecurityTokenInvalidIssuerException), EventLevel.Error);
            return null;
        }

        /// <summary>
        /// Validates the <see cref="SecurityKey"/> that signed a <see cref="SecurityToken"/>.
        /// </summary>
        /// <param name="securityKey">The <see cref="SecurityKey"/> that signed the <see cref="SecurityToken"/>.</param>
        /// <param name="securityToken">The <see cref="SecurityToken"/> being validated.</param>
        /// <param name="validationParameters"><see cref="TokenValidationParameters"/> required for validation.</param>
        /// <exception cref="ArgumentNullException"> if 'vaidationParameters' is null.</exception>
        public static void ValidateIssuerSecurityKey(SecurityKey securityKey, SecurityToken securityToken, TokenValidationParameters validationParameters)
        {
            if (validationParameters == null)
            {
                LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, ErrorMessages.IDX10000, "validationParameters"), typeof(ArgumentNullException), EventLevel.Verbose);
            }

            if (!validationParameters.ValidateIssuerSigningKey)
            {
                IdentityModelEventSource.Logger.WriteInformation("ValidateIssuerSigningKey property on ValidationParamaters is set to false. Exiting without validating the issuer signing key.");
                return;
            }

            X509SecurityKey x509SecurityKey = securityKey as X509SecurityKey;
            if (x509SecurityKey != null)
            {
                //validationParameters.CertificateValidator.Validate(x509SecurityKey.Certificate);
            }
        }

        /// <summary>
        /// Validates the lifetime of a <see cref="SecurityToken"/>.
        /// </summary>
        /// <param name="notBefore">The 'notBefore' time found in the <see cref="SecurityToken"/>.</param>
        /// <param name="expires">The 'expiration' time found in the <see cref="SecurityToken"/>.</param>
        /// <param name="securityToken">The <see cref="SecurityToken"/> being validated.</param>
        /// <param name="validationParameters"><see cref="TokenValidationParameters"/> required for validation.</param>
        /// <exception cref="ArgumentNullException"> if 'vaidationParameters' is null.</exception>
        /// <exception cref="SecurityTokenNoExpirationException"> if 'expires.HasValue' is false and <see cref="TokenValidationParameters.RequireExpirationTime"/> is true.</exception>
        /// <exception cref="SecurityTokenInvalidLifetimeException"> if 'notBefore' is &gt; 'expires'.</exception>
        /// <exception cref="SecurityTokenNotYetValidException"> if 'notBefore' is &gt; DateTime.UtcNow.</exception>
        /// <exception cref="SecurityTokenExpiredException"> if 'expires' is &lt; DateTime.UtcNow.</exception>
        /// <remarks>All time comparisons apply <see cref="TokenValidationParameters.ClockSkew"/>.</remarks>
        public static void ValidateLifetime(DateTime? notBefore, DateTime? expires, SecurityToken securityToken, TokenValidationParameters validationParameters)
        {
            if (validationParameters == null)
            {
                LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, ErrorMessages.IDX10000, "validationParameters"), typeof(ArgumentNullException), EventLevel.Verbose);
            }

            if (!validationParameters.ValidateLifetime)
            {
                IdentityModelEventSource.Logger.WriteInformation("ValidateLifetime property on ValidationParamaters is set to false. Exiting without validating the lifetime.");
                return;
            }

            if (!expires.HasValue && validationParameters.RequireExpirationTime)
            {
                LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, ErrorMessages.IDX10225, securityToken == null ? "null" : securityToken.GetType().ToString()), typeof(SecurityTokenNoExpirationException), EventLevel.Error);
            }

            if (notBefore.HasValue && expires.HasValue && (notBefore.Value > expires.Value))
            {
                LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, ErrorMessages.IDX10224, notBefore.Value, expires.Value), typeof(SecurityTokenInvalidLifetimeException), EventLevel.Error);
            }

            DateTime utcNow = DateTime.UtcNow;
            if (notBefore.HasValue && (notBefore.Value > DateTimeUtil.Add(utcNow, validationParameters.ClockSkew)))
            {
                LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, ErrorMessages.IDX10222, notBefore.Value, utcNow), typeof(SecurityTokenNotYetValidException), EventLevel.Error);
            }

            if (expires.HasValue && (expires.Value < DateTimeUtil.Add(utcNow, validationParameters.ClockSkew.Negate())))
            {
                LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, ErrorMessages.IDX10223, expires.Value, utcNow), typeof(SecurityTokenExpiredException), EventLevel.Error);
            }

            // if it reaches here, that means lifetime of the token is valid
            IdentityModelEventSource.Logger.WriteInformation("Lifetime of the token is validated.");
        }

        /// <summary>
        /// Validates if a token has been replayed.
        /// </summary>
        /// <param name="securityToken">The <see cref="SecurityToken"/> being validated.</param>
        /// <param name="expirationTime">When does the security token expire.</param>
        /// <param name="validationParameters"><see cref="TokenValidationParameters"/> required for validation.</param>
        /// <exception cref="ArgumentNullException">if 'securityToken' is null or whitespace.</exception>
        /// <exception cref="ArgumentNullException">if 'validationParameters' is null or whitespace.</exception>
        /// <exception cref="SecurityTokenNoExpirationException">if <see cref="TokenValidationParameters.TokenReplayCache"/> is not null and expirationTime.HasValue is false. When a TokenReplayCache is set, tokens require an expiration time.</exception>
        /// <exception cref="SecurityTokenReplayDetectedException">if the 'securityToken' is found in the cache.</exception>
        /// <exception cref="SecurityTokenReplayAddFailedException">if the 'securityToken' could not be added to the <see cref="TokenValidationParameters.TokenReplayCache"/>.</exception>
        public static void ValidateTokenReplay(string securityToken, DateTime? expirationTime, TokenValidationParameters validationParameters)
        {
            if (string.IsNullOrWhiteSpace(securityToken))
            {
                LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, ErrorMessages.IDX10000, "securityToken"), typeof(ArgumentNullException), EventLevel.Verbose);
            }

            if (validationParameters == null)
            {
                LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, ErrorMessages.IDX10000, "validationParameters"), typeof(ArgumentNullException), EventLevel.Verbose);
            }

            // check if token if replay cache is set, then there must be an expiration time.
            if (validationParameters.TokenReplayCache != null)
            {
                if (!expirationTime.HasValue)
                {
                    LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, ErrorMessages.IDX10227, securityToken), typeof(SecurityTokenNoExpirationException), EventLevel.Error);
                }

                if (validationParameters.TokenReplayCache.TryFind(securityToken))
                {
                    LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, ErrorMessages.IDX10228, securityToken), typeof(SecurityTokenReplayDetectedException), EventLevel.Error);
                }

                if (!validationParameters.TokenReplayCache.TryAdd(securityToken, expirationTime.Value))
                {
                    LogHelper.Throw(string.Format(CultureInfo.InvariantCulture, ErrorMessages.IDX10229, securityToken), typeof(SecurityTokenReplayAddFailedException), EventLevel.Error);
                }
            }

            // if it reaches here, that means no token replay is detected.
            IdentityModelEventSource.Logger.WriteInformation("No token replay is detected.");
        }
    }
}
