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

namespace Microsoft.IdentityModel.Protocols.SignedHttpRequest;

public partial class SignedHttpRequestHandler
{
    /// <summary>
    /// Reads a SignedHttpRequest as a <see cref="JsonWebToken"/>.
    /// </summary>
    /// <param name="signedHttpRequestValidationContext">A structure that wraps parameters needed for SignedHttpRequest validation.</param>
    /// <returns>A SignedHttpRequest as a <see cref="JsonWebToken"/>.</returns>
    internal virtual JsonWebToken ReadSignedHttpRequest(Experimental.SignedHttpRequestValidationContext signedHttpRequestValidationContext)
    {
        ValidationResult<SecurityToken, ValidationError> result = _jwtTokenHandler.ReadToken(signedHttpRequestValidationContext.SignedHttpRequest);
        return result.Result as JsonWebToken;
    }

    /// <summary>
    /// Validates the signature of the signed http request using <paramref name="popKey"/>.
    /// </summary>
    /// <param name="signedHttpRequest">A SignedHttpRequest.</param>
    /// <param name="popKey">A Pop key used to validate the signed http request signature.</param>
    /// <param name="signedHttpRequestValidationContext">A structure that wraps parameters needed for SignedHttpRequest validation.</param>
    /// <param name="cancellationToken">Propagates notification that operations should be canceled.</param>
    /// <returns>A PoP <see cref="SecurityKey"/> that validates signature of the <paramref name="signedHttpRequest"/>.</returns>
    internal virtual async Task<SecurityKey> ValidateSignatureAsync(JsonWebToken signedHttpRequest, SecurityKey popKey, Experimental.SignedHttpRequestValidationContext signedHttpRequestValidationContext, CancellationToken cancellationToken)
    {
        if (signedHttpRequestValidationContext.SignedHttpRequestValidationParameters.SignatureValidatorAsync != null)
            return await signedHttpRequestValidationContext.SignedHttpRequestValidationParameters.SignatureValidatorAsync(popKey, signedHttpRequest, signedHttpRequestValidationContext, cancellationToken).ConfigureAwait(false);

        if (popKey == null)
            throw LogHelper.LogArgumentNullException(nameof(popKey));

        if (popKey.CryptoProviderFactory == null)
            throw LogHelper.LogArgumentNullException(nameof(popKey.CryptoProviderFactory));

        try
        {
            if (popKey.CryptoProviderFactory.IsSupportedAlgorithm(signedHttpRequest.Alg, popKey))
            {
                SignatureProvider signatureProvider = null;
                try
                {
                    signatureProvider = popKey.CryptoProviderFactory.CreateForVerifying(popKey, signedHttpRequest.Alg, false);
                    if (signatureProvider == null)
                        throw LogHelper.LogExceptionMessage(
                            new InvalidOperationException(
                                LogHelper.FormatInvariant(Tokens.LogMessages.IDX10636, LogHelper.MarkAsNonPII(popKey.KeyId), LogHelper.MarkAsNonPII(signedHttpRequest.Alg))));

                    if (EncodingUtils.PerformEncodingDependentOperation<bool, string, int, SignatureProvider>(
                        signedHttpRequest.EncodedToken,
                        0,
                        signedHttpRequest.Dot2,
                        Encoding.UTF8,
                        signedHttpRequest.EncodedToken,
                        signedHttpRequest.Dot2,
                        signatureProvider,
                        JsonWebTokenHandler.ValidateSignature))

                        return popKey;
                }
                finally
                {
                    if (signatureProvider != null)
                        popKey.CryptoProviderFactory.ReleaseSignatureProvider(signatureProvider);
                }
            }
        }
        catch (Exception ex)
        {
            throw LogHelper.LogExceptionMessage(new SignedHttpRequestInvalidSignatureException(LogHelper.FormatInvariant(LogMessages.IDX23009, ex.ToString()), ex));
        }

        throw LogHelper.LogExceptionMessage(
            new SignedHttpRequestInvalidSignatureException(
                LogHelper.FormatInvariant(
                    LogMessages.IDX23034,
                    LogHelper.MarkAsUnsafeSecurityArtifact(signedHttpRequest.EncodedToken, t => t.ToString()))));
    }
}
