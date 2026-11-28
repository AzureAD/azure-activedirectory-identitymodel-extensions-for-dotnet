// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
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
        private async Task<ValidationResult<SecurityKey, ValidationError>> ResolveShrPopKeyAsync(
            JsonWebToken signedHttpRequest, SecurityToken validatedAccessToken, SignedHttpRequestValidationContext context, CancellationToken cancellationToken)
        {
            IPopKeyResolver? resolver = context.SignedHttpRequestValidationParameters.PopKeyResolver;
            if (resolver is not null)
                return await InvokeShrCallbackAsync(
                    () => resolver.ResolvePopKeyAsync(validatedAccessToken, signedHttpRequest, context, cancellationToken),
                    SignedHttpRequestValidationFailure.PopKey, nameof(resolver.ResolvePopKeyAsync), cancellationToken).ConfigureAwait(false);

            if (validatedAccessToken is not JsonWebToken jwt)
                return new ValidationError(
                    new MessageDetail(Tokens.LogMessages.IDX10001, nameof(validatedAccessToken), nameof(JsonWebToken)),
                    ValidationFailureType.SecurityTokenNotExpectedType, ValidationError.GetCurrentStackFrame());

            ValidationResult<Cnf, ValidationError> cnfResult = ReadShrCnf(jwt.InnerToken ?? jwt);
            if (!cnfResult.Succeeded)
                return cnfResult.Error!.AddCurrentStackFrame();

            return await ResolveShrPopKeyFromCnfClaimAsync(cnfResult.Result!, signedHttpRequest, jwt, context, cancellationToken).ConfigureAwait(false);
        }

        private static ValidationResult<Cnf, ValidationError> ReadShrCnf(JsonWebToken token)
        {
            if (!token.TryGetPayloadValue(ConfirmationClaimTypes.Cnf, out string json) || string.IsNullOrEmpty(json))
                return ShrError(SignedHttpRequestValidationFailure.ConfirmationClaim,
                    new MessageDetail(LogMessages.IDX23003, LogHelper.MarkAsNonPII(ConfirmationClaimTypes.Cnf)), ConfirmationClaimTypes.Cnf);

            try
            {
                return new Cnf(json);
            }
            catch (Exception ex) when (ex is JsonException || ex is ArgumentException)
            {
                return ShrError(SignedHttpRequestValidationFailure.ConfirmationClaim,
                    new MessageDetail(LogMessages.IDX23042, LogHelper.MarkAsNonPII(ConfirmationClaimTypes.Cnf)),
                    ConfirmationClaimTypes.Cnf, ex);
            }
        }

        private async Task<ValidationResult<SecurityKey, ValidationError>> ResolveShrPopKeyFromCnfClaimAsync(
            Cnf cnf, JsonWebToken? signedHttpRequest, JsonWebToken accessToken, SignedHttpRequestValidationContext context, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (cnf.JsonWebKey is not null)
            {
                if (!JsonWebKeyConverter.TryConvertToSecurityKey(cnf.JsonWebKey, out SecurityKey? key))
                    return ShrError(SignedHttpRequestValidationFailure.PopKey,
                        new MessageDetail(LogMessages.IDX23016, cnf.JsonWebKey.KeyId));

                if (key is not AsymmetricSecurityKey)
                    return ShrError(SignedHttpRequestValidationFailure.PopKey,
                        new MessageDetail(LogMessages.IDX23015, LogHelper.MarkAsNonPII(key.GetType().ToString())));

                return cnf.JsonWebKey;
            }

            if (!string.IsNullOrEmpty(cnf.Jwe))
                return await DecryptSymmetricPopKeyAsync(cnf.Jwe, context, cancellationToken).ConfigureAwait(false);

            if (!string.IsNullOrEmpty(cnf.Jku))
                return await ResolveShrPopKeyFromJkuAsync(cnf.Jku, cnf, context, cancellationToken).ConfigureAwait(false);

            if (!string.IsNullOrEmpty(cnf.Kid))
            {
                IPopKeyResolverFromKeyId? resolver = context.SignedHttpRequestValidationParameters.PopKeyResolverFromKeyId;
                if (resolver is not null)
                    return await InvokeShrCallbackAsync(
                        () => resolver.ResolvePopKeyFromKeyIdAsync(cnf.Kid, accessToken, signedHttpRequest, context, cancellationToken),
                        SignedHttpRequestValidationFailure.PopKey, nameof(resolver.ResolvePopKeyFromKeyIdAsync), cancellationToken).ConfigureAwait(false);

                if (signedHttpRequest is null)
                    return ShrError(SignedHttpRequestValidationFailure.PopKey, new MessageDetail(LogMessages.IDX23023));

                ValidationResult<Cnf, ValidationError> referenceResult = ReadShrCnf(signedHttpRequest);
                if (!referenceResult.Succeeded)
                    return referenceResult.Error!.AddCurrentStackFrame();

                // Null prevents following another SHR confirmation reference recursively.
                ValidationResult<SecurityKey, ValidationError> keyResult = await ResolveShrPopKeyFromCnfClaimAsync(referenceResult.Result!, null, accessToken, context, cancellationToken).ConfigureAwait(false);
                if (!keyResult.Succeeded)
                    return keyResult.Error!.AddCurrentStackFrame();

                string thumbprint;
                try
                {
                    SecurityKey popKey = keyResult.Result!;
                    SecurityKey thumbprintKey = popKey is JsonWebKey jwk && jwk.ConvertedSecurityKey is X509SecurityKey
                        ? jwk.ConvertedSecurityKey : popKey;
                    thumbprint = Base64UrlEncoder.Encode(thumbprintKey.ComputeJwkThumbprint());
                }
#pragma warning disable CA1031 // Keys may implement application-defined thumbprint computation.
                catch (Exception ex) when (ex is not OperationCanceledException || !cancellationToken.IsCancellationRequested)
#pragma warning restore CA1031
                {
                    return ShrError(SignedHttpRequestValidationFailure.PopKey, innerException: ex);
                }

                if (!string.Equals(cnf.Kid, thumbprint, StringComparison.Ordinal))
                    return ShrError(SignedHttpRequestValidationFailure.PopKey,
                        new MessageDetail(LogMessages.IDX23033, cnf.Kid, thumbprint, referenceResult.Result));

                return keyResult;
            }

            return ShrError(SignedHttpRequestValidationFailure.ConfirmationClaim,
                new MessageDetail(LogMessages.IDX23014, cnf), ConfirmationClaimTypes.Cnf);
        }

        private async Task<ValidationResult<SecurityKey, ValidationError>> DecryptSymmetricPopKeyAsync(
            string jwe, SignedHttpRequestValidationContext context, CancellationToken cancellationToken)
        {
            ValidationResult<SecurityToken, ValidationError> readResult = JsonWebTokenHandler.ReadToken(jwe, context.CallContext);
            if (!readResult.Succeeded)
                return ShrError(SignedHttpRequestValidationFailure.PopKey, innerValidationError: readResult.Error);

            var jwt = (JsonWebToken)readResult.Result!;
            SignedHttpRequestValidationParameters parameters = context.SignedHttpRequestValidationParameters;
            IEnumerable<SecurityKey>? keys = parameters.CnfDecryptionKeys;
            if (parameters.CnfDecryptionKeysResolver is not null)
            {
                ValidationResult<IList<SecurityKey>, ValidationError> keysResult = await InvokeShrCallbackAsync(
                    () => parameters.CnfDecryptionKeysResolver.ResolveDecryptionKeysAsync(jwt, context, cancellationToken),
                    SignedHttpRequestValidationFailure.PopKey, nameof(parameters.CnfDecryptionKeysResolver.ResolveDecryptionKeysAsync), cancellationToken).ConfigureAwait(false);
                if (!keysResult.Succeeded)
                    return keysResult.Error!.AddCurrentStackFrame();

                keys = keysResult.Result!;
            }

            if (keys is null)
                return ShrError(SignedHttpRequestValidationFailure.PopKey, new MessageDetail(LogMessages.IDX23017));

            var decryptionParameters = new ValidationParameters();
            foreach (SecurityKey key in keys)
            {
                if (key is null)
                    return ValidationError.NullParameter(nameof(keys), ValidationError.GetCurrentStackFrame());

                decryptionParameters.DecryptionKeys.Add(key);
            }

            if (decryptionParameters.DecryptionKeys.Count == 0)
                return ShrError(SignedHttpRequestValidationFailure.PopKey, new MessageDetail(LogMessages.IDX23017));

            cancellationToken.ThrowIfCancellationRequested();
            // The plaintext is JWK JSON, not a JWT. Only decrypt it; do not invoke token validation.
            ValidationResult<string, ValidationError> decryptResult;
            try
            {
                decryptResult = _jwtTokenHandler.DecryptToken(jwt, decryptionParameters, null, context.CallContext);
            }
#pragma warning disable CA1031 // Decryption may invoke application-defined crypto providers.
            catch (Exception ex) when (ex is not OperationCanceledException || !cancellationToken.IsCancellationRequested)
#pragma warning restore CA1031
            {
                return ShrError(SignedHttpRequestValidationFailure.PopKey, innerException: ex);
            }

            if (!decryptResult.Succeeded)
                return ShrError(SignedHttpRequestValidationFailure.PopKey, innerValidationError: decryptResult.Error!.AddCurrentStackFrame());

            try
            {
                var jwk = new JsonWebKey(decryptResult.Result!);
                if (JsonWebKeyConverter.TryConvertToSymmetricSecurityKey(jwk, out _))
                    return jwk;

                return ShrError(SignedHttpRequestValidationFailure.PopKey,
                    new MessageDetail(LogMessages.IDX23019, LogHelper.MarkAsNonPII(jwk.GetType().ToString())));
            }
            catch (Exception ex) when (ex is JsonException || ex is ArgumentException)
            {
                return ShrError(SignedHttpRequestValidationFailure.PopKey, innerException: ex);
            }
        }

        private async Task<ValidationResult<SecurityKey, ValidationError>> ResolveShrPopKeyFromJkuAsync(
            string jku, Cnf cnf, SignedHttpRequestValidationContext context, CancellationToken cancellationToken)
        {
            SignedHttpRequestValidationParameters parameters = context.SignedHttpRequestValidationParameters;
            if (!parameters.AllowResolvingPopKeyFromJku)
                return ShrError(SignedHttpRequestValidationFailure.PopKey, new MessageDetail(LogMessages.IDX23037));

            if (!Uri.TryCreate(jku, UriKind.Absolute, out Uri? uri) ||
                !parameters.AllowedDomainsForJkuRetrieval.Any(domain => !string.IsNullOrEmpty(domain) &&
                    (uri.Host.Equals(domain, StringComparison.OrdinalIgnoreCase) ||
                    uri.Host.EndsWith("." + domain, StringComparison.OrdinalIgnoreCase))))
                return ShrError(SignedHttpRequestValidationFailure.PopKey,
                    new MessageDetail(LogMessages.IDX23038, jku, string.Join(", ", parameters.AllowedDomainsForJkuRetrieval)));

            if (parameters.RequireHttpsForJkuResourceRetrieval && !Utility.IsHttps(jku))
                return ShrError(SignedHttpRequestValidationFailure.PopKey, new MessageDetail(LogMessages.IDX23006, jku));

            IList<JsonWebKey> keys;
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                HttpClient? client = parameters.HttpClientProvider is null ? _defaultHttpClient : parameters.HttpClientProvider();
                if (client is null)
                    return ShrError(SignedHttpRequestValidationFailure.PopKey,
                        new MessageDetail(LogMessages.IDX23041, LogHelper.MarkAsNonPII(nameof(parameters.HttpClientProvider))));

                using (HttpResponseMessage response = await client.GetAsync(uri, cancellationToken).ConfigureAwait(false))
                {
                    response.EnsureSuccessStatusCode();
                    string json = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
                    cancellationToken.ThrowIfCancellationRequested();
                    keys = new JsonWebKeySet(json).Keys;
                }
            }
#pragma warning disable CA1031 // HTTP providers and message handlers may throw arbitrary exceptions.
            catch (Exception ex) when (ex is not OperationCanceledException || !cancellationToken.IsCancellationRequested)
#pragma warning restore CA1031
            {
                return ShrError(SignedHttpRequestValidationFailure.PopKey,
                    new MessageDetail(LogMessages.IDX23039, LogHelper.MarkAsNonPII(SignedHttpRequestValidationFailure.PopKey.Name)), innerException: ex);
            }

            if (keys.Count == 0)
                return ShrError(SignedHttpRequestValidationFailure.PopKey, new MessageDetail(LogMessages.IDX23031));

            if (keys.Count == 1)
                return keys[0];

            if (string.IsNullOrEmpty(cnf.Kid))
                return ShrError(SignedHttpRequestValidationFailure.PopKey, new MessageDetail(LogMessages.IDX23035));

            foreach (JsonWebKey key in keys)
            {
                if (string.Equals(key.KeyId, cnf.Kid, StringComparison.Ordinal))
                    return key;
            }

            return ShrError(SignedHttpRequestValidationFailure.PopKey,
                new MessageDetail(LogMessages.IDX23021, cnf.Kid, string.Join(", ", keys.Select(key => key.KeyId))));
        }
    }
}
