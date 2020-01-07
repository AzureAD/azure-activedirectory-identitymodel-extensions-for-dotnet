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

using Microsoft.IdentityModel.Logging;
using System.Collections.Generic;
using System;
using System.Security.Cryptography.X509Certificates;

namespace Microsoft.IdentityModel.Tokens
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
        /// <exception cref="ArgumentNullException">If 'vaidationParameters' is null.</exception>
        /// <exception cref="ArgumentNullException">If 'audiences' is null and <see cref="TokenValidationParameters.ValidateAudience"/> is true.</exception>
        /// <exception cref="SecurityTokenInvalidAudienceException">If <see cref="TokenValidationParameters.ValidAudience"/> is null or whitespace and <see cref="TokenValidationParameters.ValidAudiences"/> is null.</exception>
        /// <exception cref="SecurityTokenInvalidAudienceException">If none of the 'audiences' matched either <see cref="TokenValidationParameters.ValidAudience"/> or one of <see cref="TokenValidationParameters.ValidAudiences"/>.</exception>
        /// <remarks>An EXACT match is required.</remarks>
        public static void ValidateAudience(IEnumerable<string> audiences, SecurityToken securityToken, TokenValidationParameters validationParameters)
        {
            if (validationParameters == null)
                throw LogHelper.LogArgumentNullException(nameof(validationParameters));

            if (validationParameters.AudienceValidator != null)
            {
                if (!validationParameters.AudienceValidator(audiences, securityToken, validationParameters))
                    throw LogHelper.LogExceptionMessage(new SecurityTokenInvalidAudienceException(LogHelper.FormatInvariant(LogMessages.IDX10231, securityToken))
                    {
                        InvalidAudience = Utility.SerializeAsSingleCommaDelimitedString(audiences)
                    });

                return;
            }

            if (!validationParameters.ValidateAudience)
            {
                LogHelper.LogWarning(LogMessages.IDX10233);
                return;
            }

            if (audiences == null)
                throw LogHelper.LogExceptionMessage(new SecurityTokenInvalidAudienceException(LogMessages.IDX10207) { InvalidAudience = null });

            if (string.IsNullOrWhiteSpace(validationParameters.ValidAudience) && (validationParameters.ValidAudiences == null))
                throw LogHelper.LogExceptionMessage(new SecurityTokenInvalidAudienceException(LogMessages.IDX10208) { InvalidAudience = Utility.SerializeAsSingleCommaDelimitedString(audiences) });

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
                            LogHelper.LogInformation(LogMessages.IDX10234, audience);
                            return;
                        }
                    }
                }

                if (!string.IsNullOrWhiteSpace(validationParameters.ValidAudience))
                {
                    if (string.Equals(audience, validationParameters.ValidAudience, StringComparison.Ordinal))
                    {
                        LogHelper.LogInformation(LogMessages.IDX10234, audience);
                        return;
                    }
                }
            }

            throw LogHelper.LogExceptionMessage(
                new SecurityTokenInvalidAudienceException(LogHelper.FormatInvariant(LogMessages.IDX10214, Utility.SerializeAsSingleCommaDelimitedString(audiences), (validationParameters.ValidAudience ?? "null"), Utility.SerializeAsSingleCommaDelimitedString(validationParameters.ValidAudiences)))
                    { InvalidAudience = Utility.SerializeAsSingleCommaDelimitedString(audiences) });
        }
    
        /// <summary>
        /// Determines if an issuer found in a <see cref="SecurityToken"/> is valid.
        /// </summary>
        /// <param name="issuer">The issuer to validate</param>
        /// <param name="securityToken">The <see cref="SecurityToken"/> that is being validated.</param>
        /// <param name="validationParameters"><see cref="TokenValidationParameters"/> required for validation.</param>
        /// <returns>The issuer to use when creating the "Claim"(s) in a "ClaimsIdentity".</returns>
        /// <exception cref="ArgumentNullException">If 'vaidationParameters' is null.</exception>
        /// <exception cref="ArgumentNullException">If 'issuer' is null or whitespace and <see cref="TokenValidationParameters.ValidateIssuer"/> is true.</exception>
        /// <exception cref="SecurityTokenInvalidIssuerException">If <see cref="TokenValidationParameters.ValidIssuer"/> is null or whitespace and <see cref="TokenValidationParameters.ValidIssuers"/> is null.</exception>
        /// <exception cref="SecurityTokenInvalidIssuerException">If 'issuer' failed to matched either <see cref="TokenValidationParameters.ValidIssuer"/> or one of <see cref="TokenValidationParameters.ValidIssuers"/>.</exception>
        /// <remarks>An EXACT match is required.</remarks>
        public static string ValidateIssuer(string issuer, SecurityToken securityToken, TokenValidationParameters validationParameters)
        {
            if (validationParameters == null)
                throw LogHelper.LogArgumentNullException(nameof(validationParameters));

            if (validationParameters.IssuerValidator != null)
                return validationParameters.IssuerValidator(issuer, securityToken, validationParameters);

            if (!validationParameters.ValidateIssuer)
            {
                LogHelper.LogInformation(LogMessages.IDX10235);
                return issuer;
            }

            if (string.IsNullOrWhiteSpace(issuer))
                throw LogHelper.LogExceptionMessage(new SecurityTokenInvalidIssuerException(LogMessages.IDX10211)
                    { InvalidIssuer = issuer });

            // Throw if all possible places to validate against are null or empty
            if (string.IsNullOrWhiteSpace(validationParameters.ValidIssuer) && (validationParameters.ValidIssuers == null))
                throw LogHelper.LogExceptionMessage(new SecurityTokenInvalidIssuerException(LogMessages.IDX10204)
                    { InvalidIssuer = issuer });

            if (string.Equals(validationParameters.ValidIssuer, issuer, StringComparison.Ordinal))
            {
                LogHelper.LogInformation(LogMessages.IDX10236, issuer);
                return issuer;
            }

            if (null != validationParameters.ValidIssuers)
            {
                foreach (string str in validationParameters.ValidIssuers)
                {
                    if (string.IsNullOrEmpty(str))
                    {
                        LogHelper.LogInformation(LogMessages.IDX10235);
                        continue;
                    }
                        
                    if (string.Equals(str, issuer, StringComparison.Ordinal))
                    {
                        LogHelper.LogInformation(LogMessages.IDX10236, issuer);
                        return issuer;
                    }
                }
            }

            throw LogHelper.LogExceptionMessage(
                new SecurityTokenInvalidIssuerException(LogHelper.FormatInvariant(LogMessages.IDX10205, issuer, (validationParameters.ValidIssuer ?? "null"), Utility.SerializeAsSingleCommaDelimitedString(validationParameters.ValidIssuers)))
                { InvalidIssuer = issuer });
        }

        /// <summary>
        /// Validates the <see cref="SecurityKey"/> that signed a <see cref="SecurityToken"/>.
        /// </summary>
        /// <param name="securityKey">The <see cref="SecurityKey"/> that signed the <see cref="SecurityToken"/>.</param>
        /// <param name="securityToken">The <see cref="SecurityToken"/> being validated.</param>
        /// <param name="validationParameters"><see cref="TokenValidationParameters"/> required for validation.</param>
        /// <exception cref="ArgumentNullException"> if 'securityKey' is null and ValidateIssuerSigningKey is true.</exception>
        /// <exception cref="ArgumentNullException"> if 'securityToken' is null and ValidateIssuerSigningKey is true.</exception>
        /// <exception cref="ArgumentNullException"> if 'vaidationParameters' is null.</exception>
        public static void ValidateIssuerSecurityKey(SecurityKey securityKey, SecurityToken securityToken, TokenValidationParameters validationParameters)
        {
            if (validationParameters == null)
                throw LogHelper.LogArgumentNullException(nameof(validationParameters));

            if (validationParameters.IssuerSigningKeyValidator != null)
            {
                if (!validationParameters.IssuerSigningKeyValidator(securityKey, securityToken, validationParameters))
                    throw LogHelper.LogExceptionMessage(new SecurityTokenInvalidSigningKeyException(LogHelper.FormatInvariant(LogMessages.IDX10232, securityKey)) { SigningKey = securityKey });
            }

            if (!validationParameters.ValidateIssuerSigningKey)
            {
                LogHelper.LogInformation(LogMessages.IDX10237);
                return;
            }

            if (!validationParameters.RequireSignedTokens && securityKey == null)
            {
                LogHelper.LogInformation(LogMessages.IDX10252);
                return;
            }
            else if (securityKey == null)
            {
                throw LogHelper.LogExceptionMessage(new ArgumentNullException(nameof(securityKey), LogMessages.IDX10253));
            }

            if (securityToken == null)
                throw LogHelper.LogArgumentNullException(nameof(securityToken));

            X509SecurityKey x509SecurityKey = securityKey as X509SecurityKey;
            if (x509SecurityKey?.Certificate is X509Certificate2 cert)
            {
                DateTime utcNow = DateTime.UtcNow;
                var notBeforeUtc = cert.NotBefore.ToUniversalTime();
                var notAfterUtc = cert.NotAfter.ToUniversalTime();

                if (notBeforeUtc > DateTimeUtil.Add(utcNow, validationParameters.ClockSkew))
                    throw LogHelper.LogExceptionMessage(new SecurityTokenInvalidSigningKeyException(LogHelper.FormatInvariant(LogMessages.IDX10248, notBeforeUtc, utcNow)));

                LogHelper.LogInformation(LogMessages.IDX10250, notBeforeUtc, utcNow);

                if (notAfterUtc < DateTimeUtil.Add(utcNow, validationParameters.ClockSkew.Negate()))
                    throw LogHelper.LogExceptionMessage(new SecurityTokenInvalidSigningKeyException(LogHelper.FormatInvariant(LogMessages.IDX10249, notAfterUtc, utcNow)));

                LogHelper.LogInformation(LogMessages.IDX10251, notAfterUtc, utcNow);
            }
        }

        /// <summary>
        /// Validates the lifetime of a <see cref="SecurityToken"/>.
        /// </summary>
        /// <param name="notBefore">The 'notBefore' time found in the <see cref="SecurityToken"/>.</param>
        /// <param name="expires">The 'expiration' time found in the <see cref="SecurityToken"/>.</param>
        /// <param name="securityToken">The <see cref="SecurityToken"/> being validated.</param>
        /// <param name="validationParameters"><see cref="TokenValidationParameters"/> required for validation.</param>
        /// <exception cref="ArgumentNullException">If 'vaidationParameters' is null.</exception>
        /// <exception cref="SecurityTokenNoExpirationException">If 'expires.HasValue' is false and <see cref="TokenValidationParameters.RequireExpirationTime"/> is true.</exception>
        /// <exception cref="SecurityTokenInvalidLifetimeException">If 'notBefore' is &gt; 'expires'.</exception>
        /// <exception cref="SecurityTokenNotYetValidException">If 'notBefore' is &gt; DateTime.UtcNow.</exception>
        /// <exception cref="SecurityTokenExpiredException">If 'expires' is &lt; DateTime.UtcNow.</exception>
        /// <remarks>All time comparisons apply <see cref="TokenValidationParameters.ClockSkew"/>.</remarks>
        public static void ValidateLifetime(DateTime? notBefore, DateTime? expires, SecurityToken securityToken, TokenValidationParameters validationParameters)
        {
            if (validationParameters == null)
                throw LogHelper.LogArgumentNullException(nameof(validationParameters));

            if (validationParameters.LifetimeValidator != null)
            {
                if (!validationParameters.LifetimeValidator(notBefore, expires, securityToken, validationParameters))
                    throw LogHelper.LogExceptionMessage(new SecurityTokenInvalidLifetimeException(LogHelper.FormatInvariant(LogMessages.IDX10230, securityToken))
                        { NotBefore = notBefore, Expires = expires });

                return;
            }

            if (!validationParameters.ValidateLifetime)
            {
                LogHelper.LogInformation(LogMessages.IDX10238);
                return;
            }

            if (!expires.HasValue && validationParameters.RequireExpirationTime)
                throw LogHelper.LogExceptionMessage(new SecurityTokenNoExpirationException(LogHelper.FormatInvariant(LogMessages.IDX10225, securityToken == null ? "null" : securityToken.GetType().ToString())));

            if (notBefore.HasValue && expires.HasValue && (notBefore.Value > expires.Value))
                throw LogHelper.LogExceptionMessage(new SecurityTokenInvalidLifetimeException(LogHelper.FormatInvariant(LogMessages.IDX10224, notBefore.Value, expires.Value))
                { NotBefore = notBefore, Expires = expires });

            DateTime utcNow = DateTime.UtcNow;
            if (notBefore.HasValue && (notBefore.Value > DateTimeUtil.Add(utcNow, validationParameters.ClockSkew)))
                throw LogHelper.LogExceptionMessage(new SecurityTokenNotYetValidException(LogHelper.FormatInvariant(LogMessages.IDX10222, notBefore.Value, utcNow))
                    { NotBefore = notBefore.Value });
 
            if (expires.HasValue && (expires.Value < DateTimeUtil.Add(utcNow, validationParameters.ClockSkew.Negate())))
                throw LogHelper.LogExceptionMessage(new SecurityTokenExpiredException(LogHelper.FormatInvariant(LogMessages.IDX10223, expires.Value, utcNow))
                    { Expires = expires.Value });

            // if it reaches here, that means lifetime of the token is valid
            LogHelper.LogInformation(LogMessages.IDX10239);
        }

        /// <summary>
        /// Validates if a token has been replayed.
        /// </summary>
        /// <param name="expirationTime">When does the security token expire.</param>
        /// <param name="securityToken">The <see cref="SecurityToken"/> being validated.</param>
        /// <param name="validationParameters"><see cref="TokenValidationParameters"/> required for validation.</param>
        /// <exception cref="ArgumentNullException">If 'securityToken' is null or whitespace.</exception>
        /// <exception cref="ArgumentNullException">If 'validationParameters' is null or whitespace.</exception>
        /// <exception cref="SecurityTokenNoExpirationException">If <see cref="TokenValidationParameters.TokenReplayCache"/> is not null and expirationTime.HasValue is false. When a TokenReplayCache is set, tokens require an expiration time.</exception>
        /// <exception cref="SecurityTokenReplayDetectedException">If the 'securityToken' is found in the cache.</exception>
        /// <exception cref="SecurityTokenReplayAddFailedException">If the 'securityToken' could not be added to the <see cref="TokenValidationParameters.TokenReplayCache"/>.</exception>
        public static void ValidateTokenReplay(DateTime? expirationTime, string securityToken, TokenValidationParameters validationParameters)
        {
            if (string.IsNullOrWhiteSpace(securityToken))
                throw LogHelper.LogArgumentNullException(nameof(securityToken));

            if (validationParameters == null)
                throw LogHelper.LogArgumentNullException(nameof(validationParameters));

            if (validationParameters.TokenReplayValidator != null)
            {
                if (!validationParameters.TokenReplayValidator(expirationTime, securityToken, validationParameters))
                    throw LogHelper.LogExceptionMessage(new SecurityTokenReplayDetectedException(LogHelper.FormatInvariant(LogMessages.IDX10228, securityToken)));
                return;
            }

            if (!validationParameters.ValidateTokenReplay)
            {
                LogHelper.LogInformation(LogMessages.IDX10246);
                return;
            }

            // check if token if replay cache is set, then there must be an expiration time.
            if (validationParameters.TokenReplayCache != null)
            {
                if (!expirationTime.HasValue)
                    throw LogHelper.LogExceptionMessage(new SecurityTokenNoExpirationException(LogHelper.FormatInvariant(LogMessages.IDX10227, securityToken)));

                if (validationParameters.TokenReplayCache.TryFind(securityToken))
                    throw LogHelper.LogExceptionMessage(new SecurityTokenReplayDetectedException(LogHelper.FormatInvariant(LogMessages.IDX10228, securityToken)));

                if (!validationParameters.TokenReplayCache.TryAdd(securityToken, expirationTime.Value))
                    throw LogHelper.LogExceptionMessage(new SecurityTokenReplayAddFailedException(LogHelper.FormatInvariant(LogMessages.IDX10229, securityToken)));
            }

            // if it reaches here, that means no token replay is detected.
            LogHelper.LogInformation(LogMessages.IDX10240);
        }

        /// <summary>
        /// Validates if a token has been replayed.
        /// </summary>
        /// <param name="securityToken">The <see cref="SecurityToken"/> being validated.</param>
        /// <param name="expirationTime">When does the security token expire.</param>
        /// <param name="validationParameters"><see cref="TokenValidationParameters"/> required for validation.</param>
        /// <exception cref="ArgumentNullException">If 'securityToken' is null or whitespace.</exception>
        /// <exception cref="ArgumentNullException">If 'validationParameters' is null or whitespace.</exception>
        /// <exception cref="SecurityTokenNoExpirationException">If <see cref="TokenValidationParameters.TokenReplayCache"/> is not null and expirationTime.HasValue is false. When a TokenReplayCache is set, tokens require an expiration time.</exception>
        /// <exception cref="SecurityTokenReplayDetectedException">If the 'securityToken' is found in the cache.</exception>
        /// <exception cref="SecurityTokenReplayAddFailedException">If the 'securityToken' could not be added to the <see cref="TokenValidationParameters.TokenReplayCache"/>.</exception>
        public static void ValidateTokenReplay(string securityToken, DateTime? expirationTime, TokenValidationParameters validationParameters)
        {
            ValidateTokenReplay(expirationTime, securityToken, validationParameters);
        }
    }
}
