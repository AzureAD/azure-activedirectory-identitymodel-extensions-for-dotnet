
// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System.Threading;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Tokens.Experimental;
using Microsoft.IdentityModel.Xml;

namespace Microsoft.IdentityModel.Tokens.Saml
{
    /// <summary>
    /// A class which contains useful methods for processing saml tokens.
    /// </summary>
    internal partial class SamlTokenUtilities
    {
        /// <summary>
        /// Returns a <see cref="SecurityKey"/> to use when validating the signature of a token.
        /// </summary>
        /// <param name="tokenKeyInfo">The <see cref="KeyInfo"/> field of the token being validated</param>
        /// <param name="validationParameters">The <see cref="ValidationParameters"/> to be used for validating the token.</param>
        /// <returns>Returns a <see cref="SecurityKey"/> to use for signature validation.</returns>
        /// <remarks>If key fails to resolve, then null is returned</remarks>
        internal static SecurityKey ResolveTokenSigningKey(KeyInfo tokenKeyInfo, ValidationParameters validationParameters)
        {
            if (tokenKeyInfo is null || validationParameters.IssuerSigningKeys is null)
                return null;

            for (int i = 0; i < validationParameters.IssuerSigningKeys.Count; i++)
            {
                if (tokenKeyInfo.MatchesKey(validationParameters.IssuerSigningKeys[i]))
                    return validationParameters.IssuerSigningKeys[i];
            }

            return null;
        }

        /// <summary>
        /// Fetches current configuration from the ConfigurationManager of <paramref name="validationParameters"/>
        /// and populates ValidIssuers and IssuerSigningKeys.
        /// </summary>
        /// <param name="validationParameters"> the token validation parameters to update.</param>
        /// <param name="cancellationToken"></param>
        /// <returns> New ValidationParameters with ValidIssuers and IssuerSigningKeys updated.</returns>
        internal static async Task<ValidationParameters> PopulateValidationParametersWithCurrentConfigurationAsync(
            ValidationParameters validationParameters,
            CancellationToken cancellationToken)
        {
            if (validationParameters.ConfigurationManager == null)
            {
                return validationParameters;
            }

            var currentConfiguration = await validationParameters.ConfigurationManager.GetBaseConfigurationAsync(cancellationToken).ConfigureAwait(false);
            var validationParametersCloned = validationParameters.Clone();

            validationParametersCloned.ValidIssuers.Add(currentConfiguration.Issuer);

            foreach (SecurityKey key in currentConfiguration.SigningKeys)
            {
                validationParametersCloned.IssuerSigningKeys.Add(key);
            }

            return validationParametersCloned;
        }
    }
}
