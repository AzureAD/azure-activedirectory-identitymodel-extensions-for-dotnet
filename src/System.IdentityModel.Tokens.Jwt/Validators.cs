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

using Microsoft.IdentityModel;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IdentityModel.Tokens;

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
                throw new ArgumentNullException("validationParameters");
            }

            if (!validationParameters.ValidateAudience)
            {
                return;
            }

            if (audiences == null)
            {
                throw new SecurityTokenInvalidAudienceException(string.Format(CultureInfo.InvariantCulture, ErrorMessages.IDX10214, Utility.SerializeAsSingleCommaDelimitedString(audiences), validationParameters.ValidAudience ?? "null", Utility.SerializeAsSingleCommaDelimitedString(validationParameters.ValidAudiences)));
            }

            if (string.IsNullOrWhiteSpace(validationParameters.ValidAudience) && (validationParameters.ValidAudiences == null))
            {
                throw new SecurityTokenInvalidAudienceException(ErrorMessages.IDX10208);
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
                            return;
                        }
                    }
                }

                if (!string.IsNullOrWhiteSpace(validationParameters.ValidAudience))
                {
                    if (string.Equals(audience, validationParameters.ValidAudience, StringComparison.Ordinal))
                    {
                        return;
                    }
                }
            }

            throw new SecurityTokenInvalidAudienceException(string.Format(CultureInfo.InvariantCulture, ErrorMessages.IDX10214, Utility.SerializeAsSingleCommaDelimitedString(audiences), validationParameters.ValidAudience ?? "null", Utility.SerializeAsSingleCommaDelimitedString(validationParameters.ValidAudiences)));
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
                throw new ArgumentNullException("validationParameters");
            }

            if (!validationParameters.ValidateIssuer)
            {
                return issuer;
            }

            if (string.IsNullOrWhiteSpace(issuer))
            {
                throw new SecurityTokenInvalidIssuerException(string.Format(CultureInfo.InvariantCulture, ErrorMessages.IDX10211));
            }

            // Throw if all possible places to validate against are null or empty
            if (string.IsNullOrWhiteSpace(validationParameters.ValidIssuer) && (validationParameters.ValidIssuers == null))
            {
                throw new SecurityTokenInvalidIssuerException(string.Format(CultureInfo.InvariantCulture, ErrorMessages.IDX10204));
            }

            if (string.Equals(validationParameters.ValidIssuer, issuer, StringComparison.Ordinal))
            {
                return issuer;
            }

            if (null != validationParameters.ValidIssuers)
            {
                foreach (string str in validationParameters.ValidIssuers)
                {
                    if (string.Equals(str, issuer, StringComparison.Ordinal))
                    {
                        return issuer;
                    }
                }
            }

            throw new SecurityTokenInvalidIssuerException(
                string.Format(CultureInfo.InvariantCulture, ErrorMessages.IDX10205, issuer, validationParameters.ValidIssuer ?? "null", Utility.SerializeAsSingleCommaDelimitedString(validationParameters.ValidIssuers)));
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
                throw new ArgumentNullException("validationParameters");
            }

            if (!validationParameters.ValidateIssuerSigningKey)
            {
                return;
            }

            X509SecurityKey x509SecurityKey = securityKey as X509SecurityKey;
            if (x509SecurityKey != null)
            {
                if (validationParameters.CertificateValidator == null)
                    throw new NullReferenceException(ErrorMessages.IDX10232);

                validationParameters.CertificateValidator.Validate(x509SecurityKey.Certificate);
                return;
            }

            throw new ArgumentOutOfRangeException("securityKey", ErrorMessages.IDX11009);
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
                throw new ArgumentNullException("validationParameters");
            }

            if (!validationParameters.ValidateLifetime)
            {
                return;
            }

            if (!expires.HasValue && validationParameters.RequireExpirationTime)
            {
                throw new SecurityTokenNoExpirationException(string.Format(CultureInfo.InvariantCulture, ErrorMessages.IDX10225, securityToken == null ? "null" : securityToken.GetType().ToString()));
            }

            if (notBefore.HasValue && expires.HasValue && (notBefore.Value > expires.Value))
            {
                throw new SecurityTokenInvalidLifetimeException(string.Format(CultureInfo.InvariantCulture, ErrorMessages.IDX10224, notBefore.Value, expires.Value));
            }

            DateTime utcNow = DateTime.UtcNow;
            if (notBefore.HasValue && (notBefore.Value > DateTimeUtil.Add(utcNow, validationParameters.ClockSkew)))
            {
                throw new SecurityTokenNotYetValidException(string.Format(CultureInfo.InvariantCulture, ErrorMessages.IDX10222, notBefore.Value, utcNow));
            }

            if (expires.HasValue && (expires.Value < DateTimeUtil.Add(utcNow, validationParameters.ClockSkew.Negate())))
            {
                throw new SecurityTokenExpiredException(string.Format(CultureInfo.InvariantCulture, ErrorMessages.IDX10223, expires.Value, utcNow));
            }
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
                throw new ArgumentNullException("securityToken");

            if (validationParameters == null)
                throw new ArgumentNullException("validationParameters");

            // check if token if replay cache is set, then there must be an expiration time.
            if (validationParameters.TokenReplayCache != null)
            {
                if (!expirationTime.HasValue)
                    throw new SecurityTokenNoExpirationException(string.Format(CultureInfo.InvariantCulture, ErrorMessages.IDX10227, securityToken));
        
                if (validationParameters.TokenReplayCache.TryFind(securityToken))
                    throw new SecurityTokenReplayDetectedException(string.Format(CultureInfo.InvariantCulture, ErrorMessages.IDX10228, securityToken));

                if (!validationParameters.TokenReplayCache.TryAdd(securityToken, expirationTime.Value))
                    throw new SecurityTokenReplayAddFailedException(string.Format(CultureInfo.InvariantCulture, ErrorMessages.IDX10229, securityToken));
            }
        }
    }
}
