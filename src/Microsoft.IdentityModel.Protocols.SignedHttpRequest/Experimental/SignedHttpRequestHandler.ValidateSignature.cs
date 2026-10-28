// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Tokens.Experimental;

#nullable enable
namespace Microsoft.IdentityModel.Protocols.SignedHttpRequest
{
    public partial class SignedHttpRequestHandler
    {
        private static async Task<ValidationResult<SecurityKey, ValidationError>> ValidateShrSignatureAsync(
            JsonWebToken signedHttpRequest, SecurityKey popKey, SignedHttpRequestValidationContext context, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ISignedHttpRequestSignatureValidator? validator = context.SignedHttpRequestValidationParameters.SignatureValidator;
            if (validator is not null)
                return await InvokeShrCallbackAsync(
                    () => validator.ValidateSignatureAsync(popKey, signedHttpRequest, context, cancellationToken),
                    SignedHttpRequestValidationFailure.Signature, nameof(validator.ValidateSignatureAsync), cancellationToken).ConfigureAwait(false);

            CryptoProviderFactory? factory = popKey.CryptoProviderFactory;
            if (factory is null)
                return ValidationError.NullParameter(nameof(popKey.CryptoProviderFactory), ValidationError.GetCurrentStackFrame());

            try
            {
                if (!factory.IsSupportedAlgorithm(signedHttpRequest.Alg, popKey))
                    return ShrError(SignedHttpRequestValidationFailure.Signature);

                SignatureProvider? provider = factory.CreateForVerifying(popKey, signedHttpRequest.Alg, false);
                if (provider is null)
                    return ShrError(SignedHttpRequestValidationFailure.Signature,
                        new MessageDetail(Tokens.LogMessages.IDX10636, LogHelper.MarkAsNonPII(popKey.KeyId), LogHelper.MarkAsNonPII(signedHttpRequest.Alg)));

                try
                {
                    if (EncodingUtils.PerformEncodingDependentOperation<bool, string, int, SignatureProvider>(
                        signedHttpRequest.EncodedToken, 0, signedHttpRequest.Dot2, Encoding.UTF8,
                        signedHttpRequest.EncodedToken, signedHttpRequest.Dot2, provider, JsonWebTokenHandler.ValidateSignature))
                        return popKey;
                }
                finally
                {
                    factory.ReleaseSignatureProvider(provider);
                }
            }
#pragma warning disable CA1031 // Crypto providers can be supplied by the application.
            catch (Exception ex) when (ex is not OperationCanceledException || !cancellationToken.IsCancellationRequested)
#pragma warning restore CA1031
            {
                return ShrError(SignedHttpRequestValidationFailure.Signature, innerException: ex);
            }

            return ShrError(SignedHttpRequestValidationFailure.Signature);
        }

        private static async Task<ValidationResult<bool, ValidationError>> ValidateShrNonceAsync(
            JsonWebToken signedHttpRequest, SecurityKey popKey, SignedHttpRequestValidationContext context, CancellationToken cancellationToken)
        {
            INonceValidator? validator = context.SignedHttpRequestValidationParameters.NonceValidator;
            if (validator is null)
                return true;

            ValidationResult<bool, ValidationError> result = await InvokeShrCallbackAsync(
                () => validator.ValidateNonceAsync(popKey, signedHttpRequest, context, cancellationToken),
                SignedHttpRequestValidationFailure.Nonce, nameof(validator.ValidateNonceAsync), cancellationToken).ConfigureAwait(false);
            if (!result.Succeeded)
                return result.Error!.AddCurrentStackFrame();

            if (!result.Result)
                return ShrError(SignedHttpRequestValidationFailure.Nonce, claimName: SignedHttpRequestClaimTypes.Nonce);

            return true;
        }
    }
}
