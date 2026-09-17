// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Tokens.Experimental;

namespace Microsoft.IdentityModel.Xml
{
    /// <summary>
    /// Represents a XmlDsig Reference element as per: https://www.w3.org/TR/2001/PR-xmldsig-core-20010820/#sec-Reference
    /// </summary>
    public partial class Reference : DSigElement
    {
#nullable enable
        /// <summary>
        /// Verifies that the <see cref="DigestValue" /> equals the hashed value of the <see cref="TokenStream"/> after
        /// <see cref="Transforms"/> have been applied.
        /// </summary>
        /// <param name="cryptoProviderFactory">supplies the <see cref="HashAlgorithm"/>.</param>
        /// <param name="callContext"> contextual information for diagnostics.</param>
        /// <returns>
        /// A <see cref="ValidationResult{TResult, TError}"/> containing this <see cref="Reference"/> if the digest is valid;
        /// otherwise, a <see cref="ValidationError"/>.
        /// </returns>
        /// <remarks>
        /// Expected XML, hashing, hash-provider, and digest-decoding failures are returned as
        /// <see cref="SignatureValidationFailure.ReferenceDigestValidationFailed"/> with the underlying
        /// exception preserved in <see cref="ValidationError.InnerException"/>.
        /// </remarks>
        internal ValidationResult<Reference, ValidationError> Verify(
            CryptoProviderFactory cryptoProviderFactory,
#pragma warning disable CA1801 // Review unused parameters
            CallContext callContext)
#pragma warning restore CA1801
        {
            if (cryptoProviderFactory is null)
                return ValidationError.NullParameter(
                    nameof(cryptoProviderFactory),
                    ValidationError.GetCurrentStackFrame());

            byte[] digest;
            byte[] expectedDigest;
            try
            {
                digest = ComputeDigest(cryptoProviderFactory);
                expectedDigest = Convert.FromBase64String(DigestValue);
            }
            catch (Exception ex) when (ex is XmlException or System.Xml.XmlException or CryptographicException
                or ArgumentException or FormatException or InvalidOperationException or NotSupportedException)
            {
                return new SignatureValidationError(
                    new MessageDetail(
                        LogMessages.IDX30201,
                        Uri ?? Id),
                    SignatureValidationFailure.ReferenceDigestValidationFailed,
                    ValidationError.GetCurrentStackFrame(),
                    ex);
            }

            if (!Utility.AreEqual(digest, expectedDigest))
                return new SignatureValidationError(
                    new MessageDetail(
                        LogMessages.IDX30201,
                        Uri ?? Id),
                    SignatureValidationFailure.ReferenceDigestValidationFailed,
                    ValidationError.GetCurrentStackFrame());

            return this;
        }
#nullable restore
    }
}
