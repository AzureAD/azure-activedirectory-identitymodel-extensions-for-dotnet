// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Tokens.Experimental;

namespace Microsoft.IdentityModel.Xml;

/// <summary>
/// Represents a XmlDsig Reference element as per: https://www.w3.org/TR/2001/PR-xmldsig-core-20010820/#sec-Reference
/// </summary>
public partial class Reference : DSigElement
{
    /// <summary>
    /// Verifies that the <see cref="DigestValue" /> equals the hashed value of the <see cref="TokenStream"/> after
    /// <see cref="Transforms"/> have been applied.
    /// </summary>
    /// <param name="key"> the <see cref="SecurityKey"/> associated with the signature being verified.</param>
    /// <param name="cryptoProviderFactory">supplies the <see cref="HashAlgorithm"/>.</param>
    /// <param name="callContext"> contextual information for diagnostics.</param>
    /// <returns>A <see cref="ValidationResult{TResult, TError}"/> containing <paramref name="key"/> on success or a <see cref="ValidationError"/> on failure.</returns>
    internal ValidationResult<SecurityKey, ValidationError> Verify(
        SecurityKey key,
        CryptoProviderFactory cryptoProviderFactory,
#pragma warning disable CA1801 // Review unused parameters
        CallContext callContext)
#pragma warning restore CA1801
    {
        if (key == null)
            return ValidationError.NullParameter(
                nameof(key),
                ValidationError.GetCurrentStackFrame());

        if (cryptoProviderFactory == null)
            return ValidationError.NullParameter(
                nameof(cryptoProviderFactory),
                ValidationError.GetCurrentStackFrame());

        byte[] digest;
        try
        {
            digest = ComputeDigest(cryptoProviderFactory);
        }
#pragma warning disable CA1031 // Do not catch general exception types
        catch (Exception ex)
#pragma warning restore CA1031 // Do not catch general exception types
        {
            return new SignatureValidationError(
                new MessageDetail(
                    LogMessages.IDX30201,
                    Uri ?? Id),
                SignatureValidationFailure.ReferenceDigestValidationFailed,
                ValidationError.GetCurrentStackFrame(),
                ex);
        }

        if (!Utility.AreEqual(digest, Convert.FromBase64String(DigestValue)))
            return new SignatureValidationError(
                new MessageDetail(
                    LogMessages.IDX30201,
                    Uri ?? Id),
                SignatureValidationFailure.ReferenceDigestValidationFailed,
                ValidationError.GetCurrentStackFrame());

        return key;
    }
}
