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
        /// Verifies the digest of all <see cref="References"/>
        /// </summary>
        /// <param name="cryptoProviderFactory">supplies any required cryptographic operators.</param>
        /// <param name="callContext"> contextual information for diagnostics.</param>
        internal SignatureValidationError? Verify(
            CryptoProviderFactory cryptoProviderFactory,
#pragma warning disable CA1801
            CallContext callContext)
#pragma warning restore CA1801
        {
            if (cryptoProviderFactory == null)
                return SignatureValidationError.NullParameter(
                    nameof(cryptoProviderFactory),
                    ValidationError.GetCurrentStackFrame());

            SignatureValidationError? validationError = null;

            for (int i = 0; i < References.Count; i++)
            {
                var reference = References[i];
                validationError = reference.Verify(cryptoProviderFactory, callContext);

                if (validationError is not null)
                {
                    validationError.AddCurrentStackFrame();
                    break;
                }
            }

            return validationError;
        }
#nullable restore
    }
}
