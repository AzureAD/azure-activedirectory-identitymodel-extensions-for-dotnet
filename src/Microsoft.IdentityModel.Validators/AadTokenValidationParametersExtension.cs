﻿// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;

namespace Microsoft.IdentityModel.Validators
{
    /// <summary>
    /// A generic class for additional validation checks on <see cref="SecurityToken"/> issued by the Microsoft identity platform (AAD).
    /// </summary>
    public static class AadTokenValidationParametersExtension
    {
        /// <summary>
        /// Enables the validation of the signing keys used by the Microsoft identity platform (AAD) against the token.
        /// </summary>
        /// <param name="tokenValidationParameters">The <see cref="TokenValidationParameters"/> that are used to validate the token.</param>
        /// <param name="cloudInstanceName">The optional cloud instance name to validate against.</param>
        public static void EnableAadSigningKeyValidation(this TokenValidationParameters tokenValidationParameters, string cloudInstanceName = null)
        {
            if (tokenValidationParameters == null)
                throw LogHelper.LogArgumentNullException(nameof(tokenValidationParameters));

            IssuerSigningKeyValidatorUsingConfiguration userProvidedIssuerSigningKeyValidatorUsingConfiguration = tokenValidationParameters.IssuerSigningKeyValidatorUsingConfiguration;
            IssuerSigningKeyValidator userProvidedIssuerSigningKeyValidator = tokenValidationParameters.IssuerSigningKeyValidator;

            tokenValidationParameters.IssuerSigningKeyValidatorUsingConfiguration = (securityKey, securityToken, tvp, config) =>
            {
                StoreValidateSigningKeyCloudInstanceName(securityKey, config, cloudInstanceName);
                ValidateSigningKeyIssuer(securityKey, securityToken, config);

                // preserve and run provided logic
                if (userProvidedIssuerSigningKeyValidatorUsingConfiguration != null)
                    return userProvidedIssuerSigningKeyValidatorUsingConfiguration(securityKey, securityToken, tvp, config);

                if (userProvidedIssuerSigningKeyValidator != null)
                    return userProvidedIssuerSigningKeyValidator(securityKey, securityToken, tvp);

                return ValidateIssuerSigningKeyCertificate(securityKey, tvp);
            };
        }

        /// <summary>
        /// Enables the validation of the issuer of the signing keys used by the Microsoft identity platform (AAD) against the issuer of the token.
        /// </summary>
        /// <param name="tokenValidationParameters">The <see cref="TokenValidationParameters"/> that are used to validate the token.</param>
        [Obsolete("Use EnableAadSigningKeyValidation(TokenValidationParameters, string) instead.")]
        public static void EnableAadSigningKeyIssuerValidation(this TokenValidationParameters tokenValidationParameters)
        {
            if (tokenValidationParameters == null)
                throw LogHelper.LogArgumentNullException(nameof(tokenValidationParameters));

            IssuerSigningKeyValidatorUsingConfiguration userProvidedIssuerSigningKeyValidatorUsingConfiguration = tokenValidationParameters.IssuerSigningKeyValidatorUsingConfiguration;
            IssuerSigningKeyValidator userProvidedIssuerSigningKeyValidator = tokenValidationParameters.IssuerSigningKeyValidator;

            tokenValidationParameters.IssuerSigningKeyValidatorUsingConfiguration = (securityKey, securityToken, tvp, config) =>
            {
                ValidateSigningKeyIssuer(securityKey, securityToken, config);

                // preserve and run provided logic
                if (userProvidedIssuerSigningKeyValidatorUsingConfiguration != null)
                    return userProvidedIssuerSigningKeyValidatorUsingConfiguration(securityKey, securityToken, tvp, config);

                if (userProvidedIssuerSigningKeyValidator != null)
                    return userProvidedIssuerSigningKeyValidator(securityKey, securityToken, tvp);

                return ValidateIssuerSigningKeyCertificate(securityKey, tvp);
            };
        }

        /// <summary>
        /// Validates the issuer signing key.
        /// </summary>
        /// <param name="securityKey">The <see cref="SecurityKey"/> that signed the <see cref="SecurityToken"/>.</param>
        /// <param name="securityToken">The <see cref="SecurityToken"/> being validated, could be a JwtSecurityToken or JsonWebToken.</param>
        /// <param name="configuration">The <see cref="BaseConfiguration"/> provided.</param>
        /// <returns><c>true</c> if the issuer of the signing key is valid; otherwise, <c>false</c>.</returns>
        internal static bool ValidateSigningKeyIssuer(SecurityKey securityKey, SecurityToken securityToken, BaseConfiguration configuration)
        {
            if (securityKey == null)
                return true;

            if (securityToken == null)
                throw LogHelper.LogArgumentNullException(nameof(securityToken));

            if (configuration is not OpenIdConnectConfiguration openIdConnectConfiguration)
                return true;

            JsonWebKey matchedKeyFromConfig = openIdConnectConfiguration.JsonWebKeySet?.Keys.FirstOrDefault(x => x != null && x.Kid == securityKey.KeyId);
            if (matchedKeyFromConfig != null && matchedKeyFromConfig.AdditionalData.TryGetValue(OpenIdProviderMetadataNames.Issuer, out object value))
            {
                string signingKeyIssuer = value as string;
                if (string.IsNullOrWhiteSpace(signingKeyIssuer))
                    return true;

                string tenantIdFromToken = GetTid(securityToken);
                if (string.IsNullOrEmpty(tenantIdFromToken))
                {
                    if (AppContextSwitches.DontFailOnMissingTid)
                        return true;

                    throw LogHelper.LogExceptionMessage(new SecurityTokenInvalidIssuerException(LogMessages.IDX40009));
                }

                string tokenIssuer = securityToken.Issuer;

#if NET6_0_OR_GREATER
                if (!string.IsNullOrEmpty(tokenIssuer) && !tokenIssuer.Contains(tenantIdFromToken, StringComparison.Ordinal))
                    throw LogHelper.LogExceptionMessage(new SecurityTokenInvalidIssuerException(LogHelper.FormatInvariant(LogMessages.IDX40004, LogHelper.MarkAsNonPII(tokenIssuer), LogHelper.MarkAsNonPII(tenantIdFromToken))));

                // creating an effectiveSigningKeyIssuer is required as signingKeyIssuer might contain {tenantid}
                string effectiveSigningKeyIssuer = signingKeyIssuer.Replace(AadIssuerValidator.TenantIdTemplate, tenantIdFromToken, StringComparison.Ordinal);
                string v2TokenIssuer = openIdConnectConfiguration.Issuer?.Replace(AadIssuerValidator.TenantIdTemplate, tenantIdFromToken, StringComparison.Ordinal);
#else
                if (!string.IsNullOrEmpty(tokenIssuer) && !tokenIssuer.Contains(tenantIdFromToken))
                    throw LogHelper.LogExceptionMessage(new SecurityTokenInvalidIssuerException(LogHelper.FormatInvariant(LogMessages.IDX40004, LogHelper.MarkAsNonPII(tokenIssuer), LogHelper.MarkAsNonPII(tenantIdFromToken))));

                // creating an effectiveSigningKeyIssuer is required as signingKeyIssuer might contain {tenantid}
                string effectiveSigningKeyIssuer = signingKeyIssuer.Replace(AadIssuerValidator.TenantIdTemplate, tenantIdFromToken);
                string v2TokenIssuer = openIdConnectConfiguration.Issuer?.Replace(AadIssuerValidator.TenantIdTemplate, tenantIdFromToken);
#endif

                // comparing effectiveSigningKeyIssuer with v2TokenIssuer is required as well because of the following scenario:
                // 1. service trusts /common/v2.0 endpoint 
                // 2. service receives a v1 token that has issuer like sts.windows.net
                // 3. signing key issuers will never match sts.windows.net as v1 endpoint doesn't have issuers attached to keys
                // v2TokenIssuer is the representation of Token.Issuer (if it was a v2 issuer)
                if (effectiveSigningKeyIssuer != tokenIssuer && effectiveSigningKeyIssuer != v2TokenIssuer)
                    throw LogHelper.LogExceptionMessage(new SecurityTokenInvalidIssuerException(LogHelper.FormatInvariant(LogMessages.IDX40005, LogHelper.MarkAsNonPII(tokenIssuer), LogHelper.MarkAsNonPII(effectiveSigningKeyIssuer))));
            }

            return true;
        }

        /// <summary>
        /// Stores the cloud instance name of the signing key in a property bag and validates it.
        /// </summary>
        /// <param name="securityKey">The <see cref="SecurityKey"/> that signed the <see cref="SecurityToken"/>.</param>
        /// <param name="configuration">The <see cref="BaseConfiguration"/> provided.</param>
        /// <param name="cloudInstanceName">The cloud instance name to validate against.</param>
        /// <returns><c>true</c> if the cloud instance name of the signing key is valid; otherwise, <c>false</c>.</returns>
        internal static bool StoreValidateSigningKeyCloudInstanceName(SecurityKey securityKey, BaseConfiguration configuration, string cloudInstanceName)
        {
            if (securityKey == null)
                return true;

            if (configuration is not OpenIdConnectConfiguration openIdConnectConfiguration)
                return true;

            JsonWebKey matchedKeyFromConfig = openIdConnectConfiguration.JsonWebKeySet?.Keys.FirstOrDefault(x => x != null && x.Kid == securityKey.KeyId);
            if (matchedKeyFromConfig != null && matchedKeyFromConfig.AdditionalData.TryGetValue(OpenIdProviderMetadataNames.CloudInstanceName, out object value))
            {
                string signingKeyCloudInstance = value as string;
                if (string.IsNullOrWhiteSpace(signingKeyCloudInstance))
                    return true;

                // Store the cloud instance name in the security key's property bag.
                securityKey.PropertyBag[OpenIdProviderMetadataNames.CloudInstanceName] = signingKeyCloudInstance;

                if (cloudInstanceName == null)
                    return true;

                if (signingKeyCloudInstance != cloudInstanceName)
                    throw LogHelper.LogExceptionMessage(
                        new SecurityTokenInvalidCloudInstanceException(LogHelper.FormatInvariant(LogMessages.IDX40012, LogHelper.MarkAsNonPII(cloudInstanceName), LogHelper.MarkAsNonPII(signingKeyCloudInstance)))
                        {
                            InvalidCloudInstance = cloudInstanceName
                        });
            }

            return true;
        }

        private static string GetTid(SecurityToken securityToken)
        {
            switch (securityToken)
            {
                case JsonWebToken jsonWebToken:
                    if (jsonWebToken.TryGetPayloadValue<string>(AadIssuerValidatorConstants.Tid, out string tid))
                    {
                        EnforceSingleClaimCaseInsensitive(jsonWebToken.PayloadClaimNames, AadIssuerValidatorConstants.Tid);
                        return tid;
                    }

                    return string.Empty;

                case JwtSecurityToken jwtSecurityToken:
                    if ((jwtSecurityToken.Payload.TryGetValue(AadIssuerValidatorConstants.Tid, out object tidObject) && tidObject is string jwtTid))
                    {
                        EnforceSingleClaimCaseInsensitive(jwtSecurityToken.Payload.Keys, AadIssuerValidatorConstants.Tid);
                        return jwtTid;
                    }

                    return string.Empty;

                default:
                    throw LogHelper.LogExceptionMessage(new SecurityTokenInvalidIssuerException(LogMessages.IDX40010));
            }
        }

        private static void EnforceSingleClaimCaseInsensitive(IEnumerable<string> keys, string claimType)
        {
            bool claimSeen = false;
            foreach (var key in keys)
            {
                if (string.Equals(key, claimType, StringComparison.OrdinalIgnoreCase))
                {
                    if (claimSeen)
                        throw LogHelper.LogExceptionMessage(new SecurityTokenInvalidIssuerException(LogHelper.FormatInvariant(LogMessages.IDX40011, claimType)));

                    claimSeen = true;
                }
            }
        }

        /// <summary>
        /// Validates the issuer signing key certificate.
        /// </summary>
        /// <param name="securityKey">The <see cref="SecurityKey"/> that signed the <see cref="SecurityToken"/>.</param>
        /// <param name="validationParameters">The <see cref="TokenValidationParameters"/> that are used to validate the token.</param>
        /// <returns><c>true</c> if the issuer signing key certificate is valid; otherwise, <c>false</c>.</returns>
        internal static bool ValidateIssuerSigningKeyCertificate(SecurityKey securityKey, TokenValidationParameters validationParameters)
        {
            if (!validationParameters.RequireSignedTokens && securityKey == null)
            {
                LogHelper.LogInformation(Tokens.LogMessages.IDX10252);
                return true;
            }
            else if (securityKey == null)
            {
                throw LogHelper.LogExceptionMessage(new ArgumentNullException(nameof(securityKey), LogMessages.IDX40007));
            }

            if (!validationParameters.ValidateIssuerSigningKey)
            {
                LogHelper.LogVerbose(Tokens.LogMessages.IDX10237);
                return true;
            }

            Tokens.Validators.ValidateIssuerSigningKeyLifeTime(securityKey, validationParameters);

            return true;
        }
    }
}
