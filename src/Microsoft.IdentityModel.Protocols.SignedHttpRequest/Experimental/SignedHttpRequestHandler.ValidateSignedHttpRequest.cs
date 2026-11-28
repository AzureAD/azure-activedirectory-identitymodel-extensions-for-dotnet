// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Runtime.CompilerServices;
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
        /// <summary>
        /// Validates an SHR using experimental access-token validation and result-based SHR validation.
        /// </summary>
        /// <param name="validationContext">The SHR, HTTP request, policies, and call context.</param>
        /// <param name="validationParameters">The experimental parameters for validating the embedded access token.</param>
        /// <param name="cancellationToken">The cancellation token.</param>
        /// <returns>The validated SHR and access token, or an error describing the failed validation.</returns>
        /// <remarks>
        /// Expected validation failures are returned as errors. Requested cancellation propagates as
        /// <see cref="OperationCanceledException"/>. The legacy validation overload is unaffected.
        /// The context's <see cref="SignedHttpRequestValidationContext.AccessTokenValidationParameters"/>
        /// is ignored; the explicit <paramref name="validationParameters"/> controls access-token validation.
        /// </remarks>
        public async Task<ValidationResult<ValidatedSignedHttpRequest, ValidationError>> ValidateSignedHttpRequestAsync(
            SignedHttpRequestValidationContext validationContext,
            ValidationParameters validationParameters,
            CancellationToken cancellationToken)
        {
            if (validationContext is null)
                return ValidationError.NullParameter(nameof(validationContext), ValidationError.GetCurrentStackFrame());

            if (validationParameters is null)
                return ValidationError.NullParameter(nameof(validationParameters), ValidationError.GetCurrentStackFrame());

            cancellationToken.ThrowIfCancellationRequested();
            if (validationContext.SignedHttpRequest.Length > _jwtTokenHandler.MaximumTokenSizeInBytes)
                return new ValidationError(
                    new MessageDetail(LogMessages.IDX23044, LogHelper.MarkAsNonPII(_jwtTokenHandler.MaximumTokenSizeInBytes)),
                    ValidationFailureType.SecurityTokenTooLarge,
                    ValidationError.GetCurrentStackFrame());

            ValidationResult<SecurityToken, ValidationError> readResult = JsonWebTokenHandler.ReadToken(validationContext.SignedHttpRequest, validationContext.CallContext);
            if (!readResult.Succeeded)
                return readResult.Error!.AddCurrentStackFrame();

            var signedHttpRequest = (JsonWebToken)readResult.Result!;
            if (signedHttpRequest.IsEncrypted || !signedHttpRequest.IsSigned)
                return ShrError(SignedHttpRequestValidationFailure.Signature, new MessageDetail(LogMessages.IDX23043));

            if (!signedHttpRequest.TryGetPayloadValue(SignedHttpRequestClaimTypes.At, out string accessToken) || string.IsNullOrEmpty(accessToken))
                return ShrError(SignedHttpRequestValidationFailure.AccessToken,
                    new MessageDetail(LogMessages.IDX23003, LogHelper.MarkAsNonPII(SignedHttpRequestClaimTypes.At)),
                    SignedHttpRequestClaimTypes.At);

            ValidationResult<ValidatedToken, ValidationError> accessTokenResult = await InvokeShrCallbackAsync(
                () => validationContext.SignedHttpRequestValidationParameters.TokenHandler.ValidateTokenAsync(
                    accessToken, validationParameters, validationContext.CallContext, cancellationToken),
                SignedHttpRequestValidationFailure.AccessToken, nameof(TokenHandler.ValidateTokenAsync), cancellationToken).ConfigureAwait(false);
            if (!accessTokenResult.Succeeded)
                return ShrError(SignedHttpRequestValidationFailure.AccessToken,
                    new MessageDetail(LogMessages.IDX23039, LogHelper.MarkAsNonPII(SignedHttpRequestValidationFailure.AccessToken.Name)),
                    SignedHttpRequestClaimTypes.At, innerValidationError: accessTokenResult.Error);

            ValidationResult<SecurityKey, ValidationError> popKeyResult = await ResolveShrPopKeyAsync(signedHttpRequest, accessTokenResult.Result!.SecurityToken, validationContext, cancellationToken).ConfigureAwait(false);
            if (!popKeyResult.Succeeded)
                return popKeyResult.Error!.AddCurrentStackFrame();

            ValidationResult<SecurityKey, ValidationError> signatureResult = await ValidateShrSignatureAsync(signedHttpRequest, popKeyResult.Result!, validationContext, cancellationToken).ConfigureAwait(false);
            if (!signatureResult.Succeeded)
                return signatureResult.Error!.AddCurrentStackFrame();

            signedHttpRequest.SigningKey = signatureResult.Result!;

            ValidationResult<bool, ValidationError> nonceResult = await ValidateShrNonceAsync(signedHttpRequest, popKeyResult.Result!, validationContext, cancellationToken).ConfigureAwait(false);
            if (!nonceResult.Succeeded)
                return nonceResult.Error!.AddCurrentStackFrame();

            ValidationResult<bool, ValidationError> payloadResult = await ValidateSignedHttpRequestPayloadAsync(signedHttpRequest, validationContext, validationParameters, cancellationToken).ConfigureAwait(false);
            if (!payloadResult.Succeeded)
                return payloadResult.Error!.AddCurrentStackFrame();

            cancellationToken.ThrowIfCancellationRequested();
            return new ValidatedSignedHttpRequest(signedHttpRequest, accessTokenResult.Result!);
        }

        private static SignedHttpRequestValidationError ShrError(
            SignedHttpRequestValidationFailure failure,
            MessageDetail? message = null,
            string? claimName = null,
            Exception? innerException = null,
            ValidationError? innerValidationError = null,
            [CallerFilePath] string filePath = "",
            [CallerLineNumber] int lineNumber = 0)
        {
            return new SignedHttpRequestValidationError(
                message ?? new MessageDetail(LogMessages.IDX23039, LogHelper.MarkAsNonPII(failure.Name)),
                failure,
                ValidationError.GetCurrentStackFrame(filePath, lineNumber, 2),
                claimName,
                innerValidationError,
                innerException);
        }

        private static async Task<ValidationResult<TResult, ValidationError>> InvokeShrCallbackAsync<TResult>(
            Func<Task<ValidationResult<TResult, ValidationError>>> callback,
            SignedHttpRequestValidationFailure failure,
            string callbackName,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                ValidationResult<TResult, ValidationError> result = await callback().ConfigureAwait(false);
                cancellationToken.ThrowIfCancellationRequested();
                if (result.Succeeded && result.Result is not null)
                    return result;

                if (!result.Succeeded && result.Error is not null)
                    return result.Error.AddCurrentStackFrame();

                return ShrError(failure, new MessageDetail(LogMessages.IDX23041, LogHelper.MarkAsNonPII(callbackName)));
            }
#pragma warning disable CA1031 // User extension points may throw arbitrary exceptions.
            catch (Exception ex) when (ex is not OperationCanceledException || !cancellationToken.IsCancellationRequested)
#pragma warning restore CA1031
            {
                return ShrError(failure, new MessageDetail(LogMessages.IDX23040, LogHelper.MarkAsNonPII(callbackName)), innerException: ex);
            }
        }
    }
}
