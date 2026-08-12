// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Tokens.Experimental;

namespace Microsoft.IdentityModel.Xml;

/// <summary>
/// Represents a XmlDsig SignedInfo element as per: https://www.w3.org/TR/2001/PR-xmldsig-core-20010820/#sec-SignedInfo
/// </summary>
public partial class SignedInfo : DSigElement
{
    /// <summary>
    /// Verifies the digest of all <see cref="References"/>
    /// </summary>
    /// <param name="key"> the <see cref="SecurityKey"/> associated with the signature being verified.</param>
    /// <param name="cryptoProviderFactory"> supplies any required cryptographic operators.</param>
    /// <param name="callContext"> contextual information for diagnostics.</param>
    internal ValidationResult<SecurityKey, ValidationError> Verify(
        SecurityKey key,
        CryptoProviderFactory cryptoProviderFactory,
        CallContext callContext)
    {
        if (key == null)
            return ValidationError.NullParameter(
                nameof(key),
                ValidationError.GetCurrentStackFrame());

        if (cryptoProviderFactory == null)
            return ValidationError.NullParameter(
                nameof(cryptoProviderFactory),
                ValidationError.GetCurrentStackFrame());

        for (int i = 0; i < References.Count; i++)
        {
            Reference reference = References[i];
            ValidationError? validationError = reference.Verify(key, cryptoProviderFactory, callContext).Error;

            if (validationError is not null)
            {
                validationError.AddCurrentStackFrame();
                return validationError;
            }
        }

        return key;
    }
}
