// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Tokens.Experimental;

namespace Microsoft.IdentityModel.Xml
{
    /// <summary>
    /// Represents a XmlDsig SignedInfo element as per: https://www.w3.org/TR/2001/PR-xmldsig-core-20010820/#sec-SignedInfo
    /// </summary>
    public partial class SignedInfo : DSigElement
    {
#nullable enable
        /// <summary>
        /// Verifies the digest of all <see cref="References"/>.
        /// </summary>
        /// <param name="key">The candidate <see cref="SecurityKey"/> associated with this validation attempt. Returned unchanged on success.</param>
        /// <param name="cryptoProviderFactory">supplies any required cryptographic operators.</param>
        /// <param name="callContext"> contextual information for diagnostics.</param>
        /// <returns>
        /// A <see cref="ValidationResult{TResult, TError}"/> containing <paramref name="key"/> if every reference digest is valid;
        /// otherwise, the first reference validation error. Success means the reference digests passed for this enclosing
        /// validation attempt, not that this method independently verified the signature.
        /// </returns>
        internal ValidationResult<SecurityKey, ValidationError> Verify(
            SecurityKey key,
            CryptoProviderFactory cryptoProviderFactory,
            CallContext callContext)
        {
            if (key is null)
                return ValidationError.NullParameter(
                    nameof(key),
                    ValidationError.GetCurrentStackFrame());

            if (cryptoProviderFactory is null)
                return ValidationError.NullParameter(
                    nameof(cryptoProviderFactory),
                    ValidationError.GetCurrentStackFrame());

            ValidationError? validationError = null;

            for (int i = 0; i < References.Count; i++)
            {
                var reference = References[i];
                validationError = reference.Verify(cryptoProviderFactory, callContext).Error;

                if (validationError is not null)
                {
                    validationError.AddCurrentStackFrame();
                    break;
                }
            }

            if (validationError is not null)
                return validationError;

            return key;
        }
#nullable restore
    }
}
