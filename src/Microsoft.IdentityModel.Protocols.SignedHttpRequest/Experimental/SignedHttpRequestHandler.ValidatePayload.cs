// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
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
        private static readonly string[] s_shrPayloadClaims =
        [
            SignedHttpRequestClaimTypes.Ts, SignedHttpRequestClaimTypes.M, SignedHttpRequestClaimTypes.U,
            SignedHttpRequestClaimTypes.P, SignedHttpRequestClaimTypes.Q, SignedHttpRequestClaimTypes.H, SignedHttpRequestClaimTypes.B
        ];

        private async Task<ValidationResult<bool, ValidationError>> ValidateSignedHttpRequestPayloadAsync(
            JsonWebToken token, SignedHttpRequestValidationContext context, ValidationParameters validationParameters, CancellationToken cancellationToken)
        {
            SignedHttpRequestValidationParameters parameters = context.SignedHttpRequestValidationParameters;
            if (parameters.ReplayValidator is not null)
            {
                ValidationResult<bool, ValidationError> replayResult = await InvokeShrCallbackAsync(
                    () => parameters.ReplayValidator.ValidateReplayAsync(token, context, cancellationToken),
                    SignedHttpRequestValidationFailure.Replay, nameof(parameters.ReplayValidator.ValidateReplayAsync), cancellationToken).ConfigureAwait(false);
                if (!replayResult.Succeeded)
                    return replayResult.Error!.AddCurrentStackFrame();

                if (!replayResult.Result)
                    return ShrError(SignedHttpRequestValidationFailure.Replay);
            }

            foreach (string claim in s_shrPayloadClaims)
            {
                cancellationToken.ThrowIfCancellationRequested();
                bool required = claim switch
                {
                    SignedHttpRequestClaimTypes.Ts => parameters.ValidateTs,
                    SignedHttpRequestClaimTypes.M => parameters.ValidateM,
                    SignedHttpRequestClaimTypes.U => parameters.ValidateU,
                    SignedHttpRequestClaimTypes.P => parameters.ValidateP,
                    SignedHttpRequestClaimTypes.Q => parameters.ValidateQ,
                    SignedHttpRequestClaimTypes.H => parameters.ValidateH,
                    _ => parameters.ValidateB
                };

                bool validateIfPresent = parameters.ValidatePresentClaims && parameters.ClaimsToValidateWhenPresent is not null
                    && parameters.ClaimsToValidateWhenPresent.Contains(claim);
                if (!ShouldValidate(token, required, validateIfPresent, claim))
                    continue;

                ValidationResult<bool, ValidationError> result = ValidateShrClaim(token, context, validationParameters, claim);
                if (!result.Succeeded)
                    return result.Error!.AddCurrentStackFrame();
            }

            return true;
        }

        private ValidationResult<bool, ValidationError> ValidateShrClaim(JsonWebToken token, SignedHttpRequestValidationContext context, ValidationParameters validationParameters, string claim)
        {
            HttpRequestData request = context.HttpRequestData;
            SignedHttpRequestValidationParameters parameters = context.SignedHttpRequestValidationParameters;
            if (claim == SignedHttpRequestClaimTypes.Ts)
            {
                if (!token.TryGetPayloadValue(claim, out long timestamp))
                    return InvalidShrClaim(claim);

                DateTime expires;
                try
                {
                    expires = EpochTime.DateTime(timestamp).Add(parameters.SignedHttpRequestLifetime);
                }
                catch (ArgumentOutOfRangeException ex)
                {
                    return InvalidShrClaim(claim, ex);
                }

                DateTime now = validationParameters.TimeProvider.GetUtcNow().UtcDateTime;
                if (now > expires)
                    return ShrError(SignedHttpRequestValidationFailure.Claim,
                        new MessageDetail(LogMessages.IDX23010, LogHelper.MarkAsNonPII(now), LogHelper.MarkAsNonPII(expires)), claim);

                return true;
            }

            if (claim == SignedHttpRequestClaimTypes.Q || claim == SignedHttpRequestClaimTypes.H)
                return ValidateShrHashClaim(token, context, claim);

            if (!token.TryGetPayloadValue(claim, out string actual) || actual is null)
                return InvalidShrClaim(claim);

            string expected;
            if (claim == SignedHttpRequestClaimTypes.M)
            {
                if (string.IsNullOrEmpty(request.Method))
                    return ValidationError.NullParameter(nameof(request.Method), ValidationError.GetCurrentStackFrame());

                expected = request.Method.Trim();
                actual = actual.Trim();
                if (string.Equals(expected, actual, StringComparison.OrdinalIgnoreCase))
                    return true;
            }
            else if (claim == SignedHttpRequestClaimTypes.B)
            {
                try
                {
                    expected = CalculateBase64UrlEncodedHash(request.Body ?? Array.Empty<byte>());
                }
                catch (CryptographicException ex)
                {
                    return InvalidShrClaim(claim, ex);
                }

                if (string.Equals(expected, actual, StringComparison.Ordinal))
                    return true;
            }
            else
            {
                if (request.Uri is null)
                    return ValidationError.NullParameter(nameof(request.Uri), ValidationError.GetCurrentStackFrame());

                if (claim == SignedHttpRequestClaimTypes.U)
                {
                    if (!request.Uri.IsAbsoluteUri)
                        return ShrError(SignedHttpRequestValidationFailure.Claim,
                            new MessageDetail(LogMessages.IDX23001, request.Uri.OriginalString), claim);

                    expected = request.Uri.Host;
                    string expectedWithPort = $"{expected}:{request.Uri.Port}";
                    if (string.Equals(expected, actual, StringComparison.OrdinalIgnoreCase) ||
                        string.Equals(expectedWithPort, actual, StringComparison.OrdinalIgnoreCase))
                        return true;

                    return ShrError(SignedHttpRequestValidationFailure.Claim,
                        new MessageDetail(LogMessages.IDX23012, LogHelper.MarkAsNonPII(claim), expected, expectedWithPort, actual), claim);
                }

                if (!Uri.TryCreate(_baseUriHelper, request.Uri, out Uri? uri))
                    return InvalidShrClaim(claim);

                ReadOnlySpan<char> expectedPath = uri.AbsolutePath.AsSpan().Trim('/');
                ReadOnlySpan<char> actualPath = actual.AsSpan().Trim('/');
                StringComparison comparison = parameters.UseCaseSensitivePClaimComparison ? StringComparison.Ordinal : StringComparison.OrdinalIgnoreCase;
                if (expectedPath.Equals(actualPath, comparison) ||
                    (comparison == StringComparison.Ordinal && ArePClaimValuesEqual(expectedPath, actualPath)))
                    return true;

                expected = expectedPath.ToString();
                actual = actualPath.ToString();
            }

            return ShrError(SignedHttpRequestValidationFailure.Claim,
                new MessageDetail(LogMessages.IDX23011, LogHelper.MarkAsNonPII(claim), expected, actual), claim);
        }

        private ValidationResult<bool, ValidationError> ValidateShrHashClaim(JsonWebToken token, SignedHttpRequestValidationContext context, string claim)
        {
            if (!token.TryGetPayloadValue(claim, out JsonElement value) ||
                value.ValueKind != JsonValueKind.Array || value.GetArrayLength() != 2 ||
                value[0].ValueKind != JsonValueKind.Array || value[1].ValueKind != JsonValueKind.String)
                return InvalidShrClaim(claim);

            bool isQuery = claim == SignedHttpRequestClaimTypes.Q;
            IDictionary<string, string> values;
            if (isQuery)
            {
                if (context.HttpRequestData.Uri is null)
                    return ValidationError.NullParameter(nameof(context.HttpRequestData.Uri), ValidationError.GetCurrentStackFrame());

                if (!Uri.TryCreate(_baseUriHelper, context.HttpRequestData.Uri, out Uri? uri))
                    return InvalidShrClaim(claim);

                values = SanitizeQueryParams(uri);
            }
            else
            {
                foreach (KeyValuePair<string, IEnumerable<string>> header in context.HttpRequestData.Headers)
                {
                    if (header.Value is null)
                        return InvalidShrClaim(claim);
                }

                values = SanitizeHeaders(context.HttpRequestData.Headers);
            }

            var buffer = new StringBuilder();
            bool first = true;
            foreach (JsonElement nameValue in value[0].EnumerateArray())
            {
                if (nameValue.ValueKind != JsonValueKind.String)
                    return InvalidShrClaim(claim);

                string name = nameValue.GetString()!;
                if (!values.TryGetValue(name, out string? requestValue))
                    return ShrError(SignedHttpRequestValidationFailure.Claim,
                        new MessageDetail(isQuery ? LogMessages.IDX23028 : LogMessages.IDX23027,
                            name, string.Join(", ", values.Keys)), claim);

                if (!first)
                    buffer.Append(isQuery ? "&" : _newlineSeparator);

                buffer.Append(name).Append(isQuery ? "=" : ": ").Append(requestValue);
                first = false;
                values.Remove(name);
            }

            bool acceptUnsigned = isQuery ? context.SignedHttpRequestValidationParameters.AcceptUnsignedQueryParameters
                : context.SignedHttpRequestValidationParameters.AcceptUnsignedHeaders;
            if (!acceptUnsigned && values.Count != 0)
                return ShrError(SignedHttpRequestValidationFailure.Claim,
                    new MessageDetail(isQuery ? LogMessages.IDX23029 : LogMessages.IDX23026, string.Join(", ", values.Keys)), claim);

            string expected;
            try
            {
                expected = CalculateBase64UrlEncodedHash(buffer.ToString());
            }
            catch (CryptographicException ex)
            {
                return InvalidShrClaim(claim, ex);
            }

            string actual = value[1].GetString()!;
            if (!string.Equals(expected, actual, StringComparison.Ordinal))
                return ShrError(SignedHttpRequestValidationFailure.Claim,
                    new MessageDetail(LogMessages.IDX23011, LogHelper.MarkAsNonPII(claim), expected, actual), claim);

            return true;
        }

        private static SignedHttpRequestValidationError InvalidShrClaim(
            string claim, Exception? innerException = null,
            [System.Runtime.CompilerServices.CallerFilePath] string filePath = "",
            [System.Runtime.CompilerServices.CallerLineNumber] int lineNumber = 0)
        {
            return ShrError(SignedHttpRequestValidationFailure.Claim,
                new MessageDetail(LogMessages.IDX23042, LogHelper.MarkAsNonPII(claim)), claim, innerException,
                filePath: filePath, lineNumber: lineNumber);
        }
    }
}
