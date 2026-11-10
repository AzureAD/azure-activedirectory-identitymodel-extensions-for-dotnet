// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.


using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Protocols.SignedHttpRequest.Experimental;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Tokens.Experimental;

namespace Microsoft.IdentityModel.Protocols.SignedHttpRequest;

public partial class SignedHttpRequestHandler
{
    /// <summary>
    /// Reads a SignedHttpRequest as a <see cref="JsonWebToken"/>.
    /// </summary>
    /// <param name="signedHttpRequestValidationContext">A structure that wraps parameters needed for SignedHttpRequest validation.</param>
    /// <returns>A validation result containing a <see cref="JsonWebToken"/> or a <see cref="ValidationError"/>.</returns>
    internal virtual ValidationResult<JsonWebToken, ValidationError> ReadSignedHttpRequest(Experimental.SignedHttpRequestValidationContext signedHttpRequestValidationContext)
    {
        if (signedHttpRequestValidationContext is null)
            return ValidationError.NullParameter(nameof(signedHttpRequestValidationContext), ValidationError.GetCurrentStackFrame());

        ValidationResult<SecurityToken, ValidationError> result = JsonWebTokenHandler.ReadToken(signedHttpRequestValidationContext.SignedHttpRequest, signedHttpRequestValidationContext.CallContext);
        if (!result.Succeeded)
            return result.Error!.AddCurrentStackFrame();

        return (JsonWebToken)result.Result!;
    }

    /// <summary>
    /// Validates a signed http request using the <paramref name="signedHttpRequestValidationContext"/>.
    /// </summary>
    /// <param name="signedHttpRequestValidationContext">A structure that wraps parameters needed for SignedHttpRequest validation.</param>
    /// <param name="cancellationToken">Propagates notification that operations should be canceled.</param>
    /// <returns>A validation result containing an <see cref="Experimental.SignedHttpRequestValidationResult"/> or a <see cref="ValidationError"/>.</returns>
    public async Task<ValidationResult<Experimental.SignedHttpRequestValidationResult, ValidationError>> ValidateSignedHttpRequestAsync(Experimental.SignedHttpRequestValidationContext signedHttpRequestValidationContext, CancellationToken cancellationToken)
    {
        if (signedHttpRequestValidationContext is null)
            return ValidationError.NullParameter(nameof(signedHttpRequestValidationContext), ValidationError.GetCurrentStackFrame());

        // read signed http request as JWT
        ValidationResult<JsonWebToken, ValidationError> readResult = ReadSignedHttpRequest(signedHttpRequestValidationContext);
        if (!readResult.Succeeded)
            return readResult.Error!.AddCurrentStackFrame();

        JsonWebToken signedHttpRequest = readResult.Result!;

        // read access token ("at")
        if (!signedHttpRequest.TryGetPayloadValue(SignedHttpRequestClaimTypes.At, out string accessToken) || string.IsNullOrEmpty(accessToken))
            return new SignedHttpRequestValidationError(
                new MessageDetail(LogMessages.IDX23003, LogHelper.MarkAsNonPII(SignedHttpRequestClaimTypes.At)),
                SignedHttpRequestValidationFailure.InvalidAtClaim,
                ValidationError.GetCurrentStackFrame());

        // validate access token ("at")
        ValidationResult<ValidatedToken, ValidationError> validationResult = await ValidateAccessTokenAsync(accessToken, signedHttpRequestValidationContext, cancellationToken).ConfigureAwait(false);
        if (!validationResult.Succeeded)
            return validationResult.Error!.AddCurrentStackFrame();

        // resolve PoP key (confirmation key)
        ValidationResult<SecurityKey, ValidationError> popKeyResult = await ResolvePopKeyAsync(signedHttpRequest, validationResult.Result.SecurityToken as JsonWebToken, signedHttpRequestValidationContext, cancellationToken).ConfigureAwait(false);
        if (!popKeyResult.Succeeded)
            return popKeyResult.Error!.AddCurrentStackFrame();

        SecurityKey popKey = popKeyResult.Result!;

        // validate signed http request signature
        ValidationResult<SecurityKey, ValidationError> signatureResult = await ValidateSignatureAsync(signedHttpRequest, popKey, signedHttpRequestValidationContext, cancellationToken).ConfigureAwait(false);
        if (!signatureResult.Succeeded)
            return signatureResult.Error!.AddCurrentStackFrame();

        signedHttpRequest.SigningKey = signatureResult.Result!;

        // validate nonce claim
        ValidationResult<bool, ValidationError> nonceResult = ValidateNonceAsync(signedHttpRequest, popKey, signedHttpRequestValidationContext, cancellationToken);
        if (!nonceResult.Succeeded)
            return nonceResult.Error!.AddCurrentStackFrame();

        // validate signed http request payload
        ValidationResult<SecurityToken, ValidationError> payloadResult = await ValidateSignedHttpRequestPayloadAsync(signedHttpRequest, signedHttpRequestValidationContext, cancellationToken).ConfigureAwait(false);
        if (!payloadResult.Succeeded)
            return payloadResult.Error!.AddCurrentStackFrame();

        return new Experimental.SignedHttpRequestValidationResult()
        {
            IsValid = true,
            AccessTokenValidationResult = validationResult,
            SignedHttpRequest = signedHttpRequest.EncodedToken,
            ValidatedSignedHttpRequest = payloadResult.Result!
        };
    }

    /// <summary>
    /// Validates the signed http request payload.
    /// </summary>
    /// <param name="signedHttpRequest">A SignedHttpRequest.</param>
    /// <param name="signedHttpRequestValidationContext">A structure that wraps parameters needed for SignedHttpRequest validation.</param>
    /// <param name="cancellationToken">Propagates notification that operations should be canceled.</param>
    /// <returns>A validation result containing the validated request or a <see cref="ValidationError"/>.</returns>
    /// <remarks>
    /// The library doesn't provide caching logic for replay validation.
    /// Use <see cref="Experimental.SignedHttpRequestValidationParameters.ReplayValidatorAsync"/> for replay validation.
    /// </remarks>
    protected internal virtual async Task<ValidationResult<SecurityToken, ValidationError>> ValidateSignedHttpRequestPayloadAsync(SecurityToken signedHttpRequest, Experimental.SignedHttpRequestValidationContext signedHttpRequestValidationContext, CancellationToken cancellationToken)
    {
        if (signedHttpRequest is null)
            return ValidationError.NullParameter(nameof(signedHttpRequest), ValidationError.GetCurrentStackFrame());

        if (signedHttpRequestValidationContext is null)
            return ValidationError.NullParameter(nameof(signedHttpRequestValidationContext), ValidationError.GetCurrentStackFrame());

        if (signedHttpRequest is not JsonWebToken jwtSignedHttpRequest)
            return new SignedHttpRequestValidationError(
                new MessageDetail(LogMessages.IDX23030, LogHelper.MarkAsNonPII(signedHttpRequest.GetType()), LogHelper.MarkAsNonPII(typeof(JsonWebToken)), signedHttpRequest),
                SignedHttpRequestValidationFailure.ValidationFailed,
                ValidationError.GetCurrentStackFrame());

        Experimental.SignedHttpRequestValidationParameters validationParameters = signedHttpRequestValidationContext.SignedHttpRequestValidationParameters;

        if (validationParameters.ReplayValidatorAsync is not null)
        {
            try
            {
                await validationParameters.ReplayValidatorAsync(jwtSignedHttpRequest, signedHttpRequestValidationContext, cancellationToken).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                return new SignedHttpRequestValidationError(
                    new MessageDetail(LogMessages.IDX23039, ex),
                    SignedHttpRequestValidationFailure.ValidationFailed,
                    ValidationError.GetCurrentStackFrame(),
                    ex);
            }
        }

        if (ShouldValidate(jwtSignedHttpRequest, validationParameters.ValidateTs, ValidateIfPresent(validationParameters, SignedHttpRequestClaimTypes.Ts), SignedHttpRequestClaimTypes.Ts))
        {
            ValidationResult<bool, ValidationError> result = ValidateTsClaim(jwtSignedHttpRequest, signedHttpRequestValidationContext);
            if (!result.Succeeded)
                return result.Error!.AddCurrentStackFrame();
        }

        if (ShouldValidate(jwtSignedHttpRequest, validationParameters.ValidateM, ValidateIfPresent(validationParameters, SignedHttpRequestClaimTypes.M), SignedHttpRequestClaimTypes.M))
        {
            ValidationResult<bool, ValidationError> result = ValidateMClaim(jwtSignedHttpRequest, signedHttpRequestValidationContext);
            if (!result.Succeeded)
                return result.Error!.AddCurrentStackFrame();
        }

        if (ShouldValidate(jwtSignedHttpRequest, validationParameters.ValidateU, ValidateIfPresent(validationParameters, SignedHttpRequestClaimTypes.U), SignedHttpRequestClaimTypes.U))
        {
            ValidationResult<bool, ValidationError> result = ValidateUClaim(jwtSignedHttpRequest, signedHttpRequestValidationContext);
            if (!result.Succeeded)
                return result.Error!.AddCurrentStackFrame();
        }

        if (ShouldValidate(jwtSignedHttpRequest, validationParameters.ValidateP, ValidateIfPresent(validationParameters, SignedHttpRequestClaimTypes.P), SignedHttpRequestClaimTypes.P))
        {
            ValidationResult<bool, ValidationError> result = ValidatePClaim(jwtSignedHttpRequest, signedHttpRequestValidationContext);
            if (!result.Succeeded)
                return result.Error!.AddCurrentStackFrame();
        }

        if (ShouldValidate(jwtSignedHttpRequest, validationParameters.ValidateQ, ValidateIfPresent(validationParameters, SignedHttpRequestClaimTypes.Q), SignedHttpRequestClaimTypes.Q))
        {
            ValidationResult<bool, ValidationError> result = ValidateQClaim(jwtSignedHttpRequest, signedHttpRequestValidationContext);
            if (!result.Succeeded)
                return result.Error!.AddCurrentStackFrame();
        }

        if (ShouldValidate(jwtSignedHttpRequest, validationParameters.ValidateH, ValidateIfPresent(validationParameters, SignedHttpRequestClaimTypes.H), SignedHttpRequestClaimTypes.H))
        {
            ValidationResult<bool, ValidationError> result = ValidateHClaim(jwtSignedHttpRequest, signedHttpRequestValidationContext);
            if (!result.Succeeded)
                return result.Error!.AddCurrentStackFrame();
        }

        if (ShouldValidate(jwtSignedHttpRequest, validationParameters.ValidateB, ValidateIfPresent(validationParameters, SignedHttpRequestClaimTypes.B), SignedHttpRequestClaimTypes.B))
        {
            ValidationResult<bool, ValidationError> result = ValidateBClaim(jwtSignedHttpRequest, signedHttpRequestValidationContext);
            if (!result.Succeeded)
                return result.Error!.AddCurrentStackFrame();
        }

        return jwtSignedHttpRequest;
    }

    private static bool ValidateIfPresent(Experimental.SignedHttpRequestValidationParameters validationParameters, string claim)
    {
        return validationParameters.ValidatePresentClaims &&
            validationParameters.ClaimsToValidateWhenPresent is not null &&
            validationParameters.ClaimsToValidateWhenPresent.Contains(claim);
    }

    /// <summary>
    /// Validates the signed http request "ts" claim.
    /// </summary>
    internal virtual ValidationResult<bool, ValidationError> ValidateTsClaim(JsonWebToken signedHttpRequest, Experimental.SignedHttpRequestValidationContext signedHttpRequestValidationContext)
    {
        if (!signedHttpRequest.TryGetPayloadValue(SignedHttpRequestClaimTypes.Ts, out long tsClaimValue))
            return new SignedHttpRequestValidationError(
                new MessageDetail(LogMessages.IDX23003, LogHelper.MarkAsNonPII(SignedHttpRequestClaimTypes.Ts)),
                SignedHttpRequestValidationFailure.InvalidTsClaim,
                ValidationError.GetCurrentStackFrame());

        DateTime utcNow = DateTime.UtcNow;
        DateTime signedHttpRequestCreationTime = EpochTime.DateTime(tsClaimValue);
        TimeSpan lifetime = signedHttpRequestValidationContext.SignedHttpRequestValidationParameters.SignedHttpRequestLifetime;
        if (lifetime.Ticks > DateTime.MaxValue.Ticks - signedHttpRequestCreationTime.Ticks)
            return new SignedHttpRequestValidationError(
                new MessageDetail(LogMessages.IDX23041, LogHelper.MarkAsNonPII(tsClaimValue), LogHelper.MarkAsNonPII(lifetime)),
                SignedHttpRequestValidationFailure.InvalidTsClaim,
                ValidationError.GetCurrentStackFrame());

        DateTime signedHttpRequestExpirationTime = signedHttpRequestCreationTime.Add(lifetime);
        if (utcNow > signedHttpRequestExpirationTime)
            return new SignedHttpRequestValidationError(
                new MessageDetail(LogMessages.IDX23010, LogHelper.MarkAsNonPII(utcNow), LogHelper.MarkAsNonPII(signedHttpRequestExpirationTime)),
                SignedHttpRequestValidationFailure.InvalidTsClaim,
                ValidationError.GetCurrentStackFrame());

        return true;
    }

    /// <summary>
    /// Validates the signed http request "m" claim.
    /// </summary>
    internal virtual ValidationResult<bool, ValidationError> ValidateMClaim(JsonWebToken signedHttpRequest, Experimental.SignedHttpRequestValidationContext signedHttpRequestValidationContext)
    {
        string expectedHttpMethod = signedHttpRequestValidationContext.HttpRequestData.Method;
        if (string.IsNullOrEmpty(expectedHttpMethod))
            return ValidationError.NullParameter(nameof(expectedHttpMethod), ValidationError.GetCurrentStackFrame());

        if (!signedHttpRequest.TryGetPayloadValue(SignedHttpRequestClaimTypes.M, out string httpMethod) || httpMethod is null)
            return new SignedHttpRequestValidationError(
                new MessageDetail(LogMessages.IDX23003, LogHelper.MarkAsNonPII(SignedHttpRequestClaimTypes.M)),
                SignedHttpRequestValidationFailure.InvalidMClaim,
                ValidationError.GetCurrentStackFrame());

        httpMethod = httpMethod.Trim();
        expectedHttpMethod = expectedHttpMethod.Trim();
        if (!string.Equals(expectedHttpMethod, httpMethod, StringComparison.OrdinalIgnoreCase))
            return new SignedHttpRequestValidationError(
                new MessageDetail(LogMessages.IDX23011, LogHelper.MarkAsNonPII(SignedHttpRequestClaimTypes.M), LogHelper.MarkAsNonPII(expectedHttpMethod), LogHelper.MarkAsNonPII(httpMethod)),
                SignedHttpRequestValidationFailure.InvalidMClaim,
                ValidationError.GetCurrentStackFrame());

        return true;
    }

    /// <summary>
    /// Validates the signed http request "u" claim.
    /// </summary>
    internal virtual ValidationResult<bool, ValidationError> ValidateUClaim(JsonWebToken signedHttpRequest, Experimental.SignedHttpRequestValidationContext signedHttpRequestValidationContext)
    {
        Uri httpRequestUri = signedHttpRequestValidationContext.HttpRequestData.Uri;
        if (httpRequestUri is null)
            return ValidationError.NullParameter(nameof(signedHttpRequestValidationContext.HttpRequestData.Uri), ValidationError.GetCurrentStackFrame());

        if (!httpRequestUri.IsAbsoluteUri)
            return new SignedHttpRequestValidationError(
                new MessageDetail(LogMessages.IDX23001, httpRequestUri.OriginalString),
                SignedHttpRequestValidationFailure.InvalidUClaim,
                ValidationError.GetCurrentStackFrame());

        if (!signedHttpRequest.TryGetPayloadValue(SignedHttpRequestClaimTypes.U, out string uClaimValue) || uClaimValue is null)
            return new SignedHttpRequestValidationError(
                new MessageDetail(LogMessages.IDX23003, LogHelper.MarkAsNonPII(SignedHttpRequestClaimTypes.U)),
                SignedHttpRequestValidationFailure.InvalidUClaim,
                ValidationError.GetCurrentStackFrame());

        string expectedUClaimValue = httpRequestUri.Host;
        string expectedUClaimValueIncludingPort = $"{expectedUClaimValue}:{httpRequestUri.Port}";
        if (!string.Equals(expectedUClaimValue, uClaimValue, StringComparison.OrdinalIgnoreCase) &&
            !string.Equals(expectedUClaimValueIncludingPort, uClaimValue, StringComparison.OrdinalIgnoreCase))
            return new SignedHttpRequestValidationError(
                new MessageDetail(LogMessages.IDX23012, LogHelper.MarkAsNonPII(SignedHttpRequestClaimTypes.U), expectedUClaimValue, expectedUClaimValueIncludingPort, uClaimValue),
                SignedHttpRequestValidationFailure.InvalidUClaim,
                ValidationError.GetCurrentStackFrame());

        return true;
    }

    /// <summary>
    /// Validates the signed http request "p" claim.
    /// </summary>
    internal virtual ValidationResult<bool, ValidationError> ValidatePClaim(JsonWebToken signedHttpRequest, Experimental.SignedHttpRequestValidationContext signedHttpRequestValidationContext)
    {
        Uri httpRequestUri = signedHttpRequestValidationContext.HttpRequestData.Uri;
        if (httpRequestUri is null)
            return ValidationError.NullParameter(nameof(signedHttpRequestValidationContext.HttpRequestData.Uri), ValidationError.GetCurrentStackFrame());

        ValidationResult<Uri, ValidationError> uriResult = GetAbsoluteUri(httpRequestUri);
        if (!uriResult.Succeeded)
            return uriResult.Error!.AddCurrentStackFrame();

        httpRequestUri = uriResult.Result!;
        if (!signedHttpRequest.TryGetPayloadValue(SignedHttpRequestClaimTypes.P, out string pClaimValue) || pClaimValue is null)
            return new SignedHttpRequestValidationError(
                new MessageDetail(LogMessages.IDX23003, LogHelper.MarkAsNonPII(SignedHttpRequestClaimTypes.P)),
                SignedHttpRequestValidationFailure.InvalidPClaim,
                ValidationError.GetCurrentStackFrame());

        ReadOnlySpan<char> pClaimValueSpan = pClaimValue.AsSpan().Trim('/');
        ReadOnlySpan<char> expectedPClaimValueSpan = httpRequestUri.AbsolutePath.AsSpan().Trim('/');
        StringComparison comparison = signedHttpRequestValidationContext.SignedHttpRequestValidationParameters.UseCaseSensitivePClaimComparison
            ? StringComparison.Ordinal
            : StringComparison.OrdinalIgnoreCase;
        if (expectedPClaimValueSpan.Equals(pClaimValueSpan, comparison) ||
            (comparison == StringComparison.Ordinal && ArePClaimValuesEqual(expectedPClaimValueSpan, pClaimValueSpan)))
            return true;

        return new SignedHttpRequestValidationError(
            new MessageDetail(LogMessages.IDX23011, LogHelper.MarkAsNonPII(SignedHttpRequestClaimTypes.P), expectedPClaimValueSpan.ToString(), pClaimValueSpan.ToString()),
            SignedHttpRequestValidationFailure.InvalidPClaim,
            ValidationError.GetCurrentStackFrame());
    }

    /// <summary>
    /// Validates the signed http request "q" claim.
    /// </summary>
    internal virtual ValidationResult<bool, ValidationError> ValidateQClaim(JsonWebToken signedHttpRequest, Experimental.SignedHttpRequestValidationContext signedHttpRequestValidationContext)
    {
        Uri httpRequestUri = signedHttpRequestValidationContext.HttpRequestData.Uri;
        if (httpRequestUri is null)
            return ValidationError.NullParameter(nameof(httpRequestUri), ValidationError.GetCurrentStackFrame());

        if (!signedHttpRequest.TryGetPayloadValue(SignedHttpRequestClaimTypes.Q, out List<object> qClaim) || qClaim is null)
            return new SignedHttpRequestValidationError(
                new MessageDetail(LogMessages.IDX23003, LogHelper.MarkAsNonPII(SignedHttpRequestClaimTypes.Q)),
                SignedHttpRequestValidationFailure.InvalidQClaim,
                ValidationError.GetCurrentStackFrame());

        ValidationResult<Uri, ValidationError> uriResult = GetAbsoluteUri(httpRequestUri);
        if (!uriResult.Succeeded)
            return uriResult.Error!.AddCurrentStackFrame();

        httpRequestUri = uriResult.Result!;
        Dictionary<string, string> sanitizedQueryParams = SanitizeQueryParams(httpRequestUri);
        if (qClaim.Count < 2 || qClaim[0] is not object[] qClaimQueryParamNames || qClaim[1] is not string qClaimBase64UrlEncodedHash ||
            qClaimQueryParamNames.Any(name => name is not string))
            return new SignedHttpRequestValidationError(
                new MessageDetail(LogMessages.IDX23024, LogHelper.MarkAsNonPII(SignedHttpRequestClaimTypes.Q), qClaim.ToString(), "Expected an array of names and a hash string."),
                SignedHttpRequestValidationFailure.InvalidQClaim,
                ValidationError.GetCurrentStackFrame());

        var stringBuffer = new StringBuilder();
        bool firstQueryParam = true;
        foreach (string queryParamName in qClaimQueryParamNames)
        {
            if (!sanitizedQueryParams.TryGetValue(queryParamName, out string queryParamsValue))
                return new SignedHttpRequestValidationError(
                    new MessageDetail(LogMessages.IDX23028, LogHelper.MarkAsNonPII(queryParamName), LogHelper.MarkAsNonPII(string.Join(", ", sanitizedQueryParams.Keys))),
                    SignedHttpRequestValidationFailure.InvalidQClaim,
                    ValidationError.GetCurrentStackFrame());

            if (!firstQueryParam)
                stringBuffer.Append('&');

            stringBuffer.Append(queryParamName).Append('=').Append(queryParamsValue);
            firstQueryParam = false;
            sanitizedQueryParams.Remove(queryParamName);
        }

        string calculatedBase64UrlEncodedHash;
        try
        {
            calculatedBase64UrlEncodedHash = CalculateBase64UrlEncodedHash(stringBuffer.ToString());
        }
        catch (Exception ex)
        {
            return new SignedHttpRequestValidationError(
                new MessageDetail(LogMessages.IDX23025, LogHelper.MarkAsNonPII(SignedHttpRequestClaimTypes.Q), ex),
                SignedHttpRequestValidationFailure.InvalidQClaim,
                ValidationError.GetCurrentStackFrame(),
                ex);
        }

        if (!signedHttpRequestValidationContext.SignedHttpRequestValidationParameters.AcceptUnsignedQueryParameters && (sanitizedQueryParams.Count != 0))
            return new SignedHttpRequestValidationError(
                new MessageDetail(LogMessages.IDX23029, LogHelper.MarkAsNonPII(string.Join(", ", sanitizedQueryParams.Keys))),
                SignedHttpRequestValidationFailure.InvalidQClaim,
                ValidationError.GetCurrentStackFrame());

        if (!string.Equals(calculatedBase64UrlEncodedHash, qClaimBase64UrlEncodedHash, StringComparison.Ordinal))
            return new SignedHttpRequestValidationError(
                new MessageDetail(LogMessages.IDX23011, LogHelper.MarkAsNonPII(SignedHttpRequestClaimTypes.Q), calculatedBase64UrlEncodedHash, qClaimBase64UrlEncodedHash),
                SignedHttpRequestValidationFailure.InvalidQClaim,
                ValidationError.GetCurrentStackFrame());

        return true;
    }

    /// <summary>
    /// Validates the signed http request "h" claim.
    /// </summary>
    internal virtual ValidationResult<bool, ValidationError> ValidateHClaim(JsonWebToken signedHttpRequest, Experimental.SignedHttpRequestValidationContext signedHttpRequestValidationContext)
    {
        if (!signedHttpRequest.TryGetPayloadValue(SignedHttpRequestClaimTypes.H, out List<object> hClaim) || hClaim is null)
            return new SignedHttpRequestValidationError(
                new MessageDetail(LogMessages.IDX23003, LogHelper.MarkAsNonPII(SignedHttpRequestClaimTypes.H)),
                SignedHttpRequestValidationFailure.InvalidHClaim,
                ValidationError.GetCurrentStackFrame());

        if (hClaim.Count < 2 || hClaim[0] is not object[] hClaimHeaderNames || hClaim[1] is not string hClaimBase64UrlEncodedHash ||
            hClaimHeaderNames.Any(name => name is not string))
            return new SignedHttpRequestValidationError(
                new MessageDetail(LogMessages.IDX23024, LogHelper.MarkAsNonPII(SignedHttpRequestClaimTypes.H), hClaim.ToString(), "Expected an array of names and a hash string."),
                SignedHttpRequestValidationFailure.InvalidHClaim,
                ValidationError.GetCurrentStackFrame());

        IDictionary<string, string> sanitizedHeaders;
        try
        {
            sanitizedHeaders = SanitizeHeaders(signedHttpRequestValidationContext.HttpRequestData.Headers);
        }
        catch (Exception ex)
        {
            return new SignedHttpRequestValidationError(
                new MessageDetail(LogMessages.IDX23025, LogHelper.MarkAsNonPII(SignedHttpRequestClaimTypes.H), ex),
                SignedHttpRequestValidationFailure.InvalidHClaim,
                ValidationError.GetCurrentStackFrame(),
                ex);
        }

        var stringBuffer = new StringBuilder();
        bool firstHeader = true;
        foreach (string headerName in hClaimHeaderNames)
        {
            if (!sanitizedHeaders.TryGetValue(headerName, out string headerValue))
                return new SignedHttpRequestValidationError(
                    new MessageDetail(LogMessages.IDX23027, LogHelper.MarkAsNonPII(headerName), LogHelper.MarkAsNonPII(string.Join(", ", sanitizedHeaders.Keys))),
                    SignedHttpRequestValidationFailure.InvalidHClaim,
                    ValidationError.GetCurrentStackFrame());

            if (!firstHeader)
                stringBuffer.Append(_newlineSeparator);

            stringBuffer.Append(headerName).Append(": ").Append(headerValue);
            firstHeader = false;
            sanitizedHeaders.Remove(headerName);
        }

        string calculatedBase64UrlEncodedHash;
        try
        {
            calculatedBase64UrlEncodedHash = CalculateBase64UrlEncodedHash(stringBuffer.ToString());
        }
        catch (Exception ex)
        {
            return new SignedHttpRequestValidationError(
                new MessageDetail(LogMessages.IDX23025, LogHelper.MarkAsNonPII(SignedHttpRequestClaimTypes.H), ex),
                SignedHttpRequestValidationFailure.InvalidHClaim,
                ValidationError.GetCurrentStackFrame(),
                ex);
        }

        if (!signedHttpRequestValidationContext.SignedHttpRequestValidationParameters.AcceptUnsignedHeaders && sanitizedHeaders.Any())
            return new SignedHttpRequestValidationError(
                new MessageDetail(LogMessages.IDX23026, LogHelper.MarkAsNonPII(string.Join(", ", sanitizedHeaders.Keys))),
                SignedHttpRequestValidationFailure.InvalidHClaim,
                ValidationError.GetCurrentStackFrame());

        if (!string.Equals(calculatedBase64UrlEncodedHash, hClaimBase64UrlEncodedHash, StringComparison.Ordinal))
            return new SignedHttpRequestValidationError(
                new MessageDetail(LogMessages.IDX23011, LogHelper.MarkAsNonPII(SignedHttpRequestClaimTypes.H), calculatedBase64UrlEncodedHash, hClaimBase64UrlEncodedHash),
                SignedHttpRequestValidationFailure.InvalidHClaim,
                ValidationError.GetCurrentStackFrame());

        return true;
    }

    /// <summary>
    /// Validates the signed http request "b" claim.
    /// </summary>
    internal virtual ValidationResult<bool, ValidationError> ValidateBClaim(JsonWebToken signedHttpRequest, Experimental.SignedHttpRequestValidationContext signedHttpRequestValidationContext)
    {
        byte[] httpRequestBody = signedHttpRequestValidationContext.HttpRequestData.Body ?? [];
        if (!signedHttpRequest.TryGetPayloadValue(SignedHttpRequestClaimTypes.B, out string bClaim) || bClaim is null)
            return new SignedHttpRequestValidationError(
                new MessageDetail(LogMessages.IDX23003, LogHelper.MarkAsNonPII(SignedHttpRequestClaimTypes.B)),
                SignedHttpRequestValidationFailure.InvalidBClaim,
                ValidationError.GetCurrentStackFrame());

        string expectedBase64UrlEncodedHash;
        try
        {
            expectedBase64UrlEncodedHash = CalculateBase64UrlEncodedHash(httpRequestBody);
        }
        catch (Exception ex)
        {
            return new SignedHttpRequestValidationError(
                new MessageDetail(LogMessages.IDX23008, LogHelper.MarkAsNonPII(SignedHttpRequestClaimTypes.B), ex),
                SignedHttpRequestValidationFailure.CreationFailed,
                ValidationError.GetCurrentStackFrame(),
                ex);
        }

        if (!string.Equals(expectedBase64UrlEncodedHash, bClaim, StringComparison.Ordinal))
            return new SignedHttpRequestValidationError(
                new MessageDetail(LogMessages.IDX23011, LogHelper.MarkAsNonPII(SignedHttpRequestClaimTypes.B), expectedBase64UrlEncodedHash, bClaim),
                SignedHttpRequestValidationFailure.InvalidBClaim,
                ValidationError.GetCurrentStackFrame());

        return true;
    }

    /// <summary>
    /// Validates an access token ("at").
    /// </summary>
    /// <param name="accessToken">An access token ("at") as a JWT.</param>
    /// <param name="signedHttpRequestValidationContext">A structure that wraps parameters needed for SignedHttpRequest validation.</param>
    /// <param name="cancellationToken">Propagates notification that operations should be canceled.</param>
    /// <returns>A validation result containing a <see cref="ValidatedToken"/> or a <see cref="ValidationError"/>.</returns>
    internal virtual async Task<ValidationResult<ValidatedToken, ValidationError>> ValidateAccessTokenAsync(string accessToken, Experimental.SignedHttpRequestValidationContext signedHttpRequestValidationContext, CancellationToken cancellationToken)
    {
        if (string.IsNullOrEmpty(accessToken))
            return ValidationError.NullParameter(nameof(accessToken), ValidationError.GetCurrentStackFrame());

        return await signedHttpRequestValidationContext.SignedHttpRequestValidationParameters.TokenHandler.ValidateTokenAsync(accessToken, signedHttpRequestValidationContext.AccessTokenValidationParameters, signedHttpRequestValidationContext.CallContext, cancellationToken).ConfigureAwait(false);
    }



    /// <summary>
    /// Validates the signature of the signed http request using <paramref name="popKey"/>.
    /// </summary>
    /// <param name="signedHttpRequest">A SignedHttpRequest.</param>
    /// <param name="popKey">A Pop key used to validate the signed http request signature.</param>
    /// <param name="signedHttpRequestValidationContext">A structure that wraps parameters needed for SignedHttpRequest validation.</param>
    /// <param name="cancellationToken">Propagates notification that operations should be canceled.</param>
    /// <returns>A PoP <see cref="SecurityKey"/> that validates signature of the <paramref name="signedHttpRequest"/>.</returns>
    internal virtual async Task<ValidationResult<SecurityKey, ValidationError>> ValidateSignatureAsync(JsonWebToken signedHttpRequest, SecurityKey popKey, Experimental.SignedHttpRequestValidationContext signedHttpRequestValidationContext, CancellationToken cancellationToken)
    {
        if (signedHttpRequestValidationContext.SignedHttpRequestValidationParameters.SignatureValidatorAsync != null)
        {
            try
            {
                return await signedHttpRequestValidationContext.SignedHttpRequestValidationParameters.SignatureValidatorAsync(popKey, signedHttpRequest, signedHttpRequestValidationContext, cancellationToken).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                return new SignedHttpRequestValidationError(
                    new MessageDetail(LogMessages.IDX23009, ex),
                    SignedHttpRequestValidationFailure.InvalidSignature,
                    ValidationError.GetCurrentStackFrame(),
                    ex);
            }
        }

        if (popKey is null)
            return ValidationError.NullParameter(nameof(popKey), ValidationError.GetCurrentStackFrame());

        if (popKey.CryptoProviderFactory is null)
            return ValidationError.NullParameter(nameof(popKey.CryptoProviderFactory), ValidationError.GetCurrentStackFrame());

        try
        {
            if (popKey.CryptoProviderFactory.IsSupportedAlgorithm(signedHttpRequest.Alg, popKey))
            {
                SignatureProvider signatureProvider = null;
                try
                {
                    signatureProvider = popKey.CryptoProviderFactory.CreateForVerifying(popKey, signedHttpRequest.Alg, false);
                    if (signatureProvider == null)
                        return new SignedHttpRequestValidationError(
                            new MessageDetail(Tokens.LogMessages.IDX10636, LogHelper.MarkAsNonPII(popKey.KeyId), LogHelper.MarkAsNonPII(signedHttpRequest.Alg)),
                            SignedHttpRequestValidationFailure.InvalidSignature,
                            ValidationError.GetCurrentStackFrame());

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
            return new SignedHttpRequestValidationError(
                new MessageDetail(LogMessages.IDX23009, ex),
                SignedHttpRequestValidationFailure.InvalidSignature,
                ValidationError.GetCurrentStackFrame(),
                ex);
        }

        return new SignedHttpRequestValidationError(
            new MessageDetail(
                LogMessages.IDX23034,
                LogHelper.MarkAsUnsafeSecurityArtifact(signedHttpRequest.EncodedToken, t => t.ToString())),
            SignedHttpRequestValidationFailure.InvalidSignature,
            ValidationError.GetCurrentStackFrame());
    }

    /// <summary>
    /// Validates the nonce claim of the signed http request.
    /// </summary>
    /// <param name="signedHttpRequest">A SignedHttpRequest.</param>
    /// <param name="popKey">A Pop key used to validate the signed http request nonce signature.</param>
    /// <param name="signedHttpRequestValidationContext">A structure that wraps parameters needed for SignedHttpRequest validation.</param>
    /// <param name="cancellationToken">Propagates notification that operations should be canceled.</param>
    /// <returns>A successful result or a <see cref="ValidationError"/>.</returns>
    internal virtual ValidationResult<bool, ValidationError> ValidateNonceAsync(JsonWebToken signedHttpRequest, SecurityKey popKey, Experimental.SignedHttpRequestValidationContext signedHttpRequestValidationContext, CancellationToken cancellationToken)
    {
        if (signedHttpRequestValidationContext.SignedHttpRequestValidationParameters.NonceValidatorAsync is null)
            return true;

        bool nonceIsValid;
        try
        {
            nonceIsValid = signedHttpRequestValidationContext.SignedHttpRequestValidationParameters.NonceValidatorAsync(popKey, signedHttpRequest, signedHttpRequestValidationContext, cancellationToken);
        }
        catch (Exception ex)
        {
            return new SignedHttpRequestValidationError(
                new MessageDetail(LogMessages.IDX23036, ex),
                SignedHttpRequestValidationFailure.InvalidNonceClaim,
                ValidationError.GetCurrentStackFrame(),
                ex);
        }

        if (!nonceIsValid)
            return new SignedHttpRequestValidationError(
                new MessageDetail("SignedHttpRequest nonce validation failed."),
                SignedHttpRequestValidationFailure.InvalidNonceClaim,
                ValidationError.GetCurrentStackFrame());

        return true;
    }

    #region Resolve PoP key

    /// <summary>
    /// Resolves a PoP <see cref="SecurityKey"/>.
    /// </summary>
    /// <param name="signedHttpRequest">A signed http request as a JWT.</param>
    /// <param name="validatedAccessToken">An access token ("at") that was already validated during the SignedHttpRequest validation process.</param>
    /// <param name="signedHttpRequestValidationContext">A structure that wraps parameters needed for SignedHttpRequest validation.</param>
    /// <param name="cancellationToken">Propagates notification that operations should be canceled.</param>
    /// <returns>A resolved PoP <see cref="SecurityKey"/>.</returns>
    internal virtual async Task<ValidationResult<SecurityKey, ValidationError>> ResolvePopKeyAsync(JsonWebToken signedHttpRequest, JsonWebToken validatedAccessToken, Experimental.SignedHttpRequestValidationContext signedHttpRequestValidationContext, CancellationToken cancellationToken)
    {
        if (signedHttpRequestValidationContext is null)
            return ValidationError.NullParameter(nameof(signedHttpRequestValidationContext), ValidationError.GetCurrentStackFrame());

        if (signedHttpRequestValidationContext.SignedHttpRequestValidationParameters.PopKeyResolverAsync != null)
        {
            try
            {
                return await signedHttpRequestValidationContext.SignedHttpRequestValidationParameters.PopKeyResolverAsync(validatedAccessToken, signedHttpRequest, signedHttpRequestValidationContext, cancellationToken).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                return new SignedHttpRequestValidationError(
                    new MessageDetail(LogMessages.IDX23040, ex),
                    SignedHttpRequestValidationFailure.InvalidPopKey,
                    ValidationError.GetCurrentStackFrame(),
                    ex);
            }
        }

        ValidationResult<Cnf, ValidationError> cnfResult = GetCnfClaimValue(signedHttpRequest, validatedAccessToken, signedHttpRequestValidationContext);
        if (!cnfResult.Succeeded)
            return cnfResult.Error!.AddCurrentStackFrame();

        ValidationResult<SecurityKey, ValidationError> result = await ResolvePopKeyFromCnfClaimAsync(cnfResult.Result!, signedHttpRequest, validatedAccessToken, signedHttpRequestValidationContext, cancellationToken).ConfigureAwait(false);
        if (!result.Succeeded)
            return result.Error!.AddCurrentStackFrame();

        return result;
    }

    /// <summary>
    /// Gets the JSON representation of the 'cnf' claim.
    /// This method expects a "cnf" claim to be present as a claim of the <paramref name="validatedAccessToken"/> ("at").
    /// </summary>
    /// <param name="signedHttpRequest">A signed http request as a JWT.</param>
    /// <param name="validatedAccessToken">An access token ("at") that was already validated during the SignedHttpRequest validation process.</param>
    /// <param name="signedHttpRequestValidationContext">A structure that wraps parameters needed for SignedHttpRequest validation.</param>
    /// <returns>JSON representation of the 'cnf' claim.</returns>
    internal virtual ValidationResult<Cnf, ValidationError> GetCnfClaimValue(JsonWebToken signedHttpRequest, JsonWebToken validatedAccessToken, Experimental.SignedHttpRequestValidationContext signedHttpRequestValidationContext)
    {
        if (validatedAccessToken is null)
            return ValidationError.NullParameter(nameof(validatedAccessToken), ValidationError.GetCurrentStackFrame());

        // use the decrypted jwt if the jwtValidatedAccessToken is encrypted.
        if (validatedAccessToken.InnerToken != null)
            validatedAccessToken = validatedAccessToken.InnerToken;

        if (!validatedAccessToken.TryGetPayloadValue(ConfirmationClaimTypes.Cnf, out string cnf) || string.IsNullOrEmpty(cnf))
            return new SignedHttpRequestValidationError(
                new MessageDetail(LogMessages.IDX23003, LogHelper.MarkAsNonPII(ConfirmationClaimTypes.Cnf)),
                SignedHttpRequestValidationFailure.InvalidCnfClaim,
                ValidationError.GetCurrentStackFrame());

        try
        {
            return new Cnf(cnf);
        }
        catch (JsonException ex)
        {
            return new SignedHttpRequestValidationError(
                new MessageDetail(LogMessages.IDX23003, LogHelper.MarkAsNonPII(ConfirmationClaimTypes.Cnf)),
                SignedHttpRequestValidationFailure.InvalidCnfClaim,
                ValidationError.GetCurrentStackFrame(),
                ex);
        }
    }

    /// <summary>
    /// Resolves a PoP <see cref="SecurityKey"/> from a confirmation ("cnf") claim.
    /// </summary>
    /// <param name="cnf">A confirmation ("cnf") claim.</param>
    /// <param name="signedHttpRequest">A signed http request as a JWT.</param>
    /// <param name="validatedAccessToken">An access token ("at") that was already validated during the SignedHttpRequest validation process.</param>
    /// <param name="signedHttpRequestValidationContext">A structure that wraps parameters needed for SignedHttpRequest validation.</param>
    /// <param name="cancellationToken">Propagates notification that operations should be canceled.</param>
    /// <returns>A resolved PoP <see cref="SecurityKey"/>.</returns>
    /// <remarks>https://datatracker.ietf.org/doc/html/rfc7800#section-3.1</remarks>
    internal virtual async Task<ValidationResult<SecurityKey, ValidationError>> ResolvePopKeyFromCnfClaimAsync(Cnf cnf, JsonWebToken signedHttpRequest, JsonWebToken validatedAccessToken, Experimental.SignedHttpRequestValidationContext signedHttpRequestValidationContext, CancellationToken cancellationToken)
    {
        if (cnf is null)
            return ValidationError.NullParameter(nameof(cnf), ValidationError.GetCurrentStackFrame());

        ValidationResult<SecurityKey, ValidationError> result;
        if (cnf.JsonWebKey != null)
            result = ResolvePopKeyFromJwk(cnf.JsonWebKey, signedHttpRequestValidationContext);
        else if (!string.IsNullOrEmpty(cnf.Jwe))
            result = await ResolvePopKeyFromJweAsync(cnf.Jwe, signedHttpRequestValidationContext, cancellationToken).ConfigureAwait(false);
        else if (!string.IsNullOrEmpty(cnf.Jku))
            result = await ResolvePopKeyFromJkuAsync(cnf.Jku, cnf, signedHttpRequestValidationContext, cancellationToken).ConfigureAwait(false);
        else if (!string.IsNullOrEmpty(cnf.Kid))
            result = await ResolvePopKeyFromKeyIdentifierAsync(cnf.Kid, signedHttpRequest, validatedAccessToken, signedHttpRequestValidationContext, cancellationToken).ConfigureAwait(false);
        else
            return new SignedHttpRequestValidationError(
                new MessageDetail(LogMessages.IDX23014, cnf.ToString()),
                SignedHttpRequestValidationFailure.InvalidCnfClaim,
                ValidationError.GetCurrentStackFrame());

        if (!result.Succeeded)
            return result.Error!.AddCurrentStackFrame();

        return result;
    }

    /// <summary>
    /// Resolves a PoP <see cref="SecurityKey"/> from the asymmetric representation of a PoP key.
    /// </summary>
    /// <param name="jsonWebKey">The JsonWebKey to resolve.</param>
    /// <param name="signedHttpRequestValidationContext">A structure that wraps parameters needed for SignedHttpRequest validation.</param>
    /// <returns>A resolved PoP <see cref="SecurityKey"/>.</returns>
    internal virtual ValidationResult<SecurityKey, ValidationError> ResolvePopKeyFromJwk(JsonWebKey jsonWebKey, Experimental.SignedHttpRequestValidationContext signedHttpRequestValidationContext)
    {
        if (jsonWebKey is null)
            return ValidationError.NullParameter(nameof(jsonWebKey), ValidationError.GetCurrentStackFrame());

        if (JsonWebKeyConverter.TryConvertToSecurityKey(jsonWebKey, out SecurityKey key))
        {
            if (key is AsymmetricSecurityKey)
                return jsonWebKey;
            else
                return new SignedHttpRequestValidationError(
                    new MessageDetail(LogMessages.IDX23015, LogHelper.MarkAsNonPII(key.GetType().ToString())),
                    SignedHttpRequestValidationFailure.InvalidPopKey,
                    ValidationError.GetCurrentStackFrame());
        }
        else
            return new SignedHttpRequestValidationError(
                new MessageDetail(LogMessages.IDX23016, LogHelper.MarkAsNonPII(jsonWebKey.KeyId)),
                SignedHttpRequestValidationFailure.InvalidPopKey,
                ValidationError.GetCurrentStackFrame());
    }

    /// <summary>
    /// Resolves a PoP <see cref="SecurityKey"/> from the encrypted symmetric representation of a PoP key.
    /// </summary>
    /// <param name="jwe">An encrypted symmetric representation of a PoP key (JSON).</param>
    /// <param name="signedHttpRequestValidationContext">A structure that wraps parameters needed for SignedHttpRequest validation.</param>
    /// <param name="cancellationToken">Propagates notification that operations should be canceled.</param>
    /// <returns>A resolved PoP <see cref="SecurityKey"/>.</returns>
    internal virtual async Task<ValidationResult<SecurityKey, ValidationError>> ResolvePopKeyFromJweAsync(string jwe, Experimental.SignedHttpRequestValidationContext signedHttpRequestValidationContext, CancellationToken cancellationToken)
    {
        if (string.IsNullOrEmpty(jwe))
            return ValidationError.NullParameter(nameof(jwe), ValidationError.GetCurrentStackFrame());

        JsonWebKey jwk;
        try
        {
            jwk = await SignedHttpRequestUtilities.DecryptSymmetricPopKeyAsync(_jwtTokenHandler, jwe, signedHttpRequestValidationContext, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            return new SignedHttpRequestValidationError(
                new MessageDetail(LogMessages.IDX23040, ex),
                SignedHttpRequestValidationFailure.InvalidPopKey,
                ValidationError.GetCurrentStackFrame(),
                ex);
        }

        if (JsonWebKeyConverter.TryConvertToSymmetricSecurityKey(jwk, out _))
            return jwk;

        return new SignedHttpRequestValidationError(
            new MessageDetail(LogMessages.IDX23019, LogHelper.MarkAsNonPII(jwk.GetType().ToString())),
            SignedHttpRequestValidationFailure.InvalidPopKey,
            ValidationError.GetCurrentStackFrame());
    }

    /// <summary>
    /// Resolves a PoP <see cref="SecurityKey"/> from the URL reference to a PoP key.
    /// </summary>
    /// <param name="jkuSetUrl">A URL reference to a PoP JWK set.</param>
    /// <param name="cnf">A confirmation ("cnf") claim as a JObject.</param>
    /// <param name="signedHttpRequestValidationContext">A structure that wraps parameters needed for SignedHttpRequest validation.</param>
    /// <param name="cancellationToken">Propagates notification that operations should be canceled.</param>
    /// <returns>A resolved PoP <see cref="SecurityKey"/>.</returns>
    internal virtual async Task<ValidationResult<SecurityKey, ValidationError>> ResolvePopKeyFromJkuAsync(string jkuSetUrl, Cnf cnf, Experimental.SignedHttpRequestValidationContext signedHttpRequestValidationContext, CancellationToken cancellationToken)
    {
        if (signedHttpRequestValidationContext.SignedHttpRequestValidationParameters.AllowResolvingPopKeyFromJku == false)
        {
            return new SignedHttpRequestValidationError(
                new MessageDetail(LogMessages.IDX23037),
                SignedHttpRequestValidationFailure.InvalidPopKey,
                ValidationError.GetCurrentStackFrame());
        }

        if (!IsJkuUriInListOfAllowedDomains(jkuSetUrl, signedHttpRequestValidationContext))
        {
            string allowedDomains = string.Join(", ", signedHttpRequestValidationContext.SignedHttpRequestValidationParameters.AllowedDomainsForJkuRetrieval ?? []);
            return new SignedHttpRequestValidationError(
                new MessageDetail(LogMessages.IDX23038, jkuSetUrl, allowedDomains),
                SignedHttpRequestValidationFailure.InvalidPopKey,
                ValidationError.GetCurrentStackFrame());
        }

        ValidationResult<IList<SecurityKey>, ValidationError> popKeysResult = await GetPopKeysFromJkuAsync(jkuSetUrl, signedHttpRequestValidationContext, cancellationToken).ConfigureAwait(false);
        if (!popKeysResult.Succeeded)
            return popKeysResult.Error!.AddCurrentStackFrame();

        IList<SecurityKey> popKeys = popKeysResult.Result!;

        if (popKeys == null || popKeys.Count == 0)
            return new SignedHttpRequestValidationError(
                new MessageDetail(LogMessages.IDX23031),
                SignedHttpRequestValidationFailure.InvalidPopKey,
                ValidationError.GetCurrentStackFrame());

        if (popKeys.Count == 1)
        {
            return popKeys[0];
        }

        // If there are multiple keys in the referenced JWK Set document, a "kid" member MUST also be included
        // with the referenced key's JWK also containing the same "kid" value.
        // https://datatracker.ietf.org/doc/html/rfc7800#section-3.5
        else if (!string.IsNullOrEmpty(cnf.Kid))
        {
            foreach (SecurityKey key in popKeys)
            {
                if (string.Equals(key.KeyId, cnf.Kid))
                    return key;
            }

            return new SignedHttpRequestValidationError(
                new MessageDetail(
                    LogMessages.IDX23021,
                    LogHelper.MarkAsNonPII(cnf.Kid),
                    LogHelper.MarkAsNonPII(string.Join(", ", popKeys.Select(x => x.KeyId ?? "Null")))),
                SignedHttpRequestValidationFailure.InvalidPopKey,
                ValidationError.GetCurrentStackFrame());
        }
        else
        {
            return new SignedHttpRequestValidationError(
                new MessageDetail(LogMessages.IDX23035),
                SignedHttpRequestValidationFailure.InvalidPopKey,
                ValidationError.GetCurrentStackFrame());
        }
    }

    /// <summary>
    /// Gets a JWK set of PoP <see cref="SecurityKey"/> from the <paramref name="jkuSetUrl"/>.
    /// </summary>
    /// <param name="jkuSetUrl">A URL reference to a PoP JWK set.</param>
    /// <param name="signedHttpRequestValidationContext">A structure that wraps parameters needed for SignedHttpRequest validation.</param>
    /// <param name="cancellationToken">Propagates notification that operations should be canceled.</param>
    /// <returns>A collection of PoP <see cref="SecurityKey"/>.</returns>
    internal virtual async Task<ValidationResult<IList<SecurityKey>, ValidationError>> GetPopKeysFromJkuAsync(string jkuSetUrl, Experimental.SignedHttpRequestValidationContext signedHttpRequestValidationContext, CancellationToken cancellationToken)
    {
        if (string.IsNullOrEmpty(jkuSetUrl))
            return ValidationError.NullParameter(nameof(jkuSetUrl), ValidationError.GetCurrentStackFrame());

        if (!Utility.IsHttps(jkuSetUrl) && signedHttpRequestValidationContext.SignedHttpRequestValidationParameters.RequireHttpsForJkuResourceRetrieval)
            return new SignedHttpRequestValidationError(
                new MessageDetail(LogMessages.IDX23006, jkuSetUrl),
                SignedHttpRequestValidationFailure.InvalidPopKey,
                ValidationError.GetCurrentStackFrame());

        try
        {
            HttpClient httpClient = signedHttpRequestValidationContext.SignedHttpRequestValidationParameters.HttpClientProvider?.Invoke() ?? _defaultHttpClient;
            var uri = new Uri(jkuSetUrl, UriKind.RelativeOrAbsolute);
            HttpResponseMessage response = await httpClient.GetAsync(uri, cancellationToken).ConfigureAwait(false);
            string jsonWebKey = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
            var jsonWebKeySet = new JsonWebKeySet(jsonWebKey);
            return jsonWebKeySet.Keys.Cast<SecurityKey>().ToList();
        }
        catch (Exception e)
        {
            return new SignedHttpRequestValidationError(
                new MessageDetail(LogMessages.IDX23022, jkuSetUrl, e),
                SignedHttpRequestValidationFailure.InvalidPopKey,
                ValidationError.GetCurrentStackFrame(),
                e);
        }
    }

    /// <summary>
    /// Resolves a PoP <see cref="SecurityKey"/> using a key identifier of a PoP key.
    /// </summary>
    /// <param name="kid">A <see cref="ConfirmationClaimTypes.Kid"/> claim value.</param>
    /// <param name="signedHttpRequest">A signed http request as a JWT.</param>
    /// <param name="validatedAccessToken">An access token ("at") that was already validated during the SignedHttpRequest validation process.</param>
    /// <param name="signedHttpRequestValidationContext">A structure that wraps parameters needed for SignedHttpRequest validation.</param>
    /// <param name="cancellationToken">Propagates notification that operations should be canceled.</param>
    /// <returns>A resolved PoP <see cref="SecurityKey"/>.</returns>
    /// <remarks>
    /// To resolve a PoP <see cref="SecurityKey"/> using only the 'kid' claim, set the <see cref="SignedHttpRequestValidationParameters.PopKeyResolverFromKeyIdAsync"/> delegate.
    /// </remarks>
    internal virtual async Task<ValidationResult<SecurityKey, ValidationError>> ResolvePopKeyFromKeyIdentifierAsync(string kid, JsonWebToken signedHttpRequest, JsonWebToken validatedAccessToken, Experimental.SignedHttpRequestValidationContext signedHttpRequestValidationContext, CancellationToken cancellationToken)
    {
        if (signedHttpRequestValidationContext.SignedHttpRequestValidationParameters.PopKeyResolverFromKeyIdAsync != null)
        {
            try
            {
                return await signedHttpRequestValidationContext.SignedHttpRequestValidationParameters.PopKeyResolverFromKeyIdAsync(kid, validatedAccessToken, signedHttpRequest, signedHttpRequestValidationContext, cancellationToken).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                return new SignedHttpRequestValidationError(
                    new MessageDetail(LogMessages.IDX23040, ex),
                    SignedHttpRequestValidationFailure.InvalidPopKey,
                    ValidationError.GetCurrentStackFrame(),
                    ex);
            }
        }
        else if (signedHttpRequest != null && signedHttpRequest.TryGetPayloadValue(ConfirmationClaimTypes.Cnf, out string signedHttpRequestCnf) && signedHttpRequestCnf != null)
        {
            if (signedHttpRequestCnf.Length == 0)
                return new SignedHttpRequestValidationError(
                    new MessageDetail(LogMessages.IDX23003, LogHelper.MarkAsNonPII(ConfirmationClaimTypes.Cnf)),
                    SignedHttpRequestValidationFailure.InvalidCnfClaim,
                    ValidationError.GetCurrentStackFrame());

            Cnf confirmationClaim;
            try
            {
                confirmationClaim = new Cnf(signedHttpRequestCnf);
            }
            catch (JsonException ex)
            {
                return new SignedHttpRequestValidationError(
                    new MessageDetail(LogMessages.IDX23003, LogHelper.MarkAsNonPII(ConfirmationClaimTypes.Cnf)),
                    SignedHttpRequestValidationFailure.InvalidCnfClaim,
                    ValidationError.GetCurrentStackFrame(),
                    ex);
            }

            ValidationResult<SecurityKey, ValidationError> result = await ResolvePopKeyFromCnfReferenceAsync(kid, confirmationClaim, validatedAccessToken, signedHttpRequestValidationContext, cancellationToken).ConfigureAwait(false);
            if (!result.Succeeded)
                return result.Error!.AddCurrentStackFrame();

            return result;
        }
        else
            return new SignedHttpRequestValidationError(
                new MessageDetail(LogMessages.IDX23023),
                SignedHttpRequestValidationFailure.InvalidPopKey,
                ValidationError.GetCurrentStackFrame());
    }

    /// <summary>
    /// Resolves a PoP key from a "cnf" reference and validates the reference.
    /// </summary>
    /// <param name="cnfReferenceId">A reference to the root "cnf" claim, as base64url-encoded JWK thumbprint.</param>
    /// <param name="confirmationClaim">A confirmation ("cnf") claim.</param>
    /// <param name="validatedAccessToken">An access token ("at") that was already validated during the SignedHttpRequest validation process.</param>
    /// <param name="signedHttpRequestValidationContext">A structure that wraps parameters needed for SignedHttpRequest validation.</param>
    /// <param name="cancellationToken">Propagates notification that operations should be canceled.</param>
    /// <returns>A resolved PoP <see cref="SecurityKey"/>.</returns>
    /// <remarks><paramref name="cnfReferenceId"/> MUST match the base64url-encoded thumbprint of a JWK resolved from the <paramref name="confirmationClaim"/>.</remarks>
    internal virtual async Task<ValidationResult<SecurityKey, ValidationError>> ResolvePopKeyFromCnfReferenceAsync(string cnfReferenceId, Cnf confirmationClaim, JsonWebToken validatedAccessToken, Experimental.SignedHttpRequestValidationContext signedHttpRequestValidationContext, CancellationToken cancellationToken)
    {
        // resolve PoP key from the confirmation claim, but set signedHttpRequest to null to prevent recursion.
        ValidationResult<SecurityKey, ValidationError> popKeyResult = await ResolvePopKeyFromCnfClaimAsync(confirmationClaim, null, validatedAccessToken, signedHttpRequestValidationContext, cancellationToken).ConfigureAwait(false);
        if (!popKeyResult.Succeeded)
            return popKeyResult.Error!.AddCurrentStackFrame();

        SecurityKey popKey = popKeyResult.Result!;

        string jwkPopKeyThumprint;
        // if the cnf key is an X509SecurityKey ('x5c'), JWK thumbprint has to be calculated on its underlying RSA key.
        try
        {
            if (popKey is JsonWebKey jwtPopKey && jwtPopKey.ConvertedSecurityKey is X509SecurityKey)
                jwkPopKeyThumprint = Base64UrlEncoder.Encode(jwtPopKey.ConvertedSecurityKey.ComputeJwkThumbprint());
            else
                jwkPopKeyThumprint = Base64UrlEncoder.Encode(popKey.ComputeJwkThumbprint());
        }
        catch (Exception ex)
        {
            return new SignedHttpRequestValidationError(
                new MessageDetail(LogMessages.IDX23040, ex),
                SignedHttpRequestValidationFailure.InvalidPopKey,
                ValidationError.GetCurrentStackFrame(),
                ex);
        }

        // validate reference
        if (!string.Equals(cnfReferenceId, jwkPopKeyThumprint))
            return new SignedHttpRequestValidationError(
                new MessageDetail(LogMessages.IDX23033, cnfReferenceId, jwkPopKeyThumprint, confirmationClaim),
                SignedHttpRequestValidationFailure.InvalidPopKey,
                ValidationError.GetCurrentStackFrame());

        return popKey;
    }
    #endregion

    #region Private utility methods

    private ValidationResult<Uri, ValidationError> GetAbsoluteUri(Uri uri)
    {
        if (uri.IsAbsoluteUri)
            return uri;

        if (Uri.TryCreate(_baseUriHelper, uri, out Uri absoluteUri))
            return absoluteUri;

        return new SignedHttpRequestValidationError(
            new MessageDetail(LogMessages.IDX23007, uri.OriginalString),
            SignedHttpRequestValidationFailure.CreationFailed,
            ValidationError.GetCurrentStackFrame());
    }

    private static bool IsJkuUriInListOfAllowedDomains(string jkuSetUrl, Experimental.SignedHttpRequestValidationContext signedHttpRequestValidationContext)
    {
        if (string.IsNullOrEmpty(jkuSetUrl))
            return false;

        if (signedHttpRequestValidationContext.SignedHttpRequestValidationParameters.AllowedDomainsForJkuRetrieval.Count == 0)
            return false;

        if (!Uri.TryCreate(jkuSetUrl, UriKind.Absolute, out Uri uri))
            return false;

        return signedHttpRequestValidationContext.SignedHttpRequestValidationParameters.AllowedDomainsForJkuRetrieval.Any(domain =>
            uri.Host.Equals(domain, StringComparison.OrdinalIgnoreCase) ||
            uri.Host.EndsWith("." + domain, StringComparison.OrdinalIgnoreCase));
    }
    #endregion
}
