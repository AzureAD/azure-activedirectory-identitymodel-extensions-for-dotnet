// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.IO;
using System.Text;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Tokens.Experimental;

namespace Microsoft.IdentityModel.Xml
{
    /// <summary>
    /// Represents a XmlDsig Signature element as per: https://www.w3.org/TR/2001/PR-xmldsig-core-20010820/#sec-Signature
    /// </summary>
    public partial class Signature : DSigElement
    {
#nullable enable
        /// <summary>
        /// Verifies the signature over <see cref="SignedInfo"/> and then the reference digests.
        /// </summary>
        /// <param name="key">the <see cref="SecurityKey"/> to use for cryptographic operations.</param>
        /// <param name="cryptoProviderFactory">the <see cref="CryptoProviderFactory"/> to obtain cryptographic operators.</param>
        /// <param name="callContext"> contextual information for diagnostics.</param>
        /// <returns>
        /// A <see cref="ValidationResult{TResult, TError}"/> containing <paramref name="key"/> if the signature and all
        /// reference digests are valid; otherwise, a <see cref="ValidationError"/>.
        /// </returns>
        internal ValidationResult<SecurityKey, ValidationError> Verify(
            SecurityKey key,
            CryptoProviderFactory cryptoProviderFactory,
#pragma warning disable CA1801 // Review unused parameters
            CallContext callContext)
#pragma warning restore CA1801
        {
            if (key is null)
                return ValidationError.NullParameter(
                    nameof(key),
                    ValidationError.GetCurrentStackFrame());

            if (cryptoProviderFactory is null)
                return ValidationError.NullParameter(
                    nameof(cryptoProviderFactory),
                    ValidationError.GetCurrentStackFrame());

            if (SignedInfo is null)
                return new SignatureValidationError(
                    new MessageDetail(LogMessages.IDX30212),
                    ValidationFailureType.SignedInfoNull,
                    ValidationError.GetCurrentStackFrame());

            if (!cryptoProviderFactory.IsSupportedAlgorithm(SignedInfo.SignatureMethod, key))
                return new SignatureValidationError(
                    new MessageDetail(LogMessages.IDX30207, SignedInfo.SignatureMethod, cryptoProviderFactory.GetType()),
                    ValidationFailureType.CryptoProviderFactoryDoesNotSupportAlgorithm,
                    ValidationError.GetCurrentStackFrame());

            var signatureProvider = cryptoProviderFactory.CreateForVerifying(key, SignedInfo.SignatureMethod);
            if (signatureProvider is null)
                return new SignatureValidationError(
                    new MessageDetail(LogMessages.IDX30203, cryptoProviderFactory, LogHelper.MarkAsNonPII(key.KeyId), SignedInfo.SignatureMethod),
                    ValidationFailureType.CryptoProviderReturnedNull,
                    ValidationError.GetCurrentStackFrame());

            try
            {
                using (var memoryStream = new MemoryStream())
                {
                    SignedInfo.GetCanonicalBytes(memoryStream);
                    if (!signatureProvider.Verify(memoryStream.ToArray(), Convert.FromBase64String(SignatureValue)))
                    {
                        StringBuilder keyAttempted = new StringBuilder().Append(key.ToString()).Append(", KeyId: ").AppendLine(key.KeyId);
                        return new SignatureValidationError(
                            new MessageDetail(Tokens.LogMessages.IDX10520,
                            LogHelper.MarkAsNonPII(keyAttempted.ToString())),
                            SignatureValidationFailure.ValidationFailed,
                            ValidationError.GetCurrentStackFrame());
                    }
                }

                ValidationResult<SecurityKey, ValidationError> signedInfoResult =
                    SignedInfo.Verify(key, cryptoProviderFactory, callContext);

                if (!signedInfoResult.Succeeded)
                    return signedInfoResult.Error!.AddCurrentStackFrame();

                return signedInfoResult;
            }
            finally
            {
                if (signatureProvider is not null)
                    cryptoProviderFactory.ReleaseSignatureProvider(signatureProvider);
            }
        }
#nullable restore
    }
}
