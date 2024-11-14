// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System.Collections.Generic;
using System.Text;
using Microsoft.IdentityModel.Tokens.Saml;
using Microsoft.IdentityModel.Xml;
using TokenLogMessages = Microsoft.IdentityModel.Tokens.LogMessages;

#nullable enable
namespace Microsoft.IdentityModel.Tokens.Saml2
{
    public partial class Saml2SecurityTokenHandler : SecurityTokenHandler
    {
        internal static ValidationResult<SecurityKey> ValidateSignature(
            Saml2SecurityToken samlToken,
            ValidationParameters validationParameters,
            CallContext callContext)
        {
            if (samlToken is null)
            {
                return ValidationError.NullParameter(
                    nameof(samlToken),
                    ValidationError.GetCurrentStackFrame());
            }

            if (validationParameters is null)
            {
                return ValidationError.NullParameter(
                    nameof(validationParameters),
                    ValidationError.GetCurrentStackFrame());
            }

            // Delegate is set by the user, we call it and return the result.
            if (validationParameters.SignatureValidator is not null)
                return validationParameters.SignatureValidator(samlToken, validationParameters, null, callContext);

            // If the user wants to accept unsigned tokens, they must set validationParameters.SignatureValidator
            if (samlToken.Assertion.Signature is null)
                return new XmlValidationError(
                    new MessageDetail(
                        TokenLogMessages.IDX10504,
                        samlToken.Assertion.CanonicalString),
                    ValidationFailureType.TokenIsNotSigned,
                    typeof(SecurityTokenValidationException),
                    ValidationError.GetCurrentStackFrame());

            SecurityKey? resolvedKey = null;
            bool keyMatched = false;

            if (validationParameters.IssuerSigningKeyResolver is not null)
            {
                resolvedKey = validationParameters.IssuerSigningKeyResolver(
                    samlToken.Assertion.CanonicalString,
                    samlToken,
                    samlToken.Assertion.Signature.KeyInfo?.Id,
                    validationParameters,
                    null,
                    callContext);
            }
            else
            {
                resolvedKey = SamlTokenUtilities.ResolveTokenSigningKey(samlToken.Assertion.Signature.KeyInfo, validationParameters);
            }

            ValidationError? error = null;

            if (resolvedKey is not null)
            {
                keyMatched = true;
                var result = ValidateSignatureUsingKey(resolvedKey, samlToken, validationParameters, callContext);
                if (result.IsValid)
                    return result;

                error = result.UnwrapError();
            }

            bool canMatchKey = samlToken.Assertion.Signature.KeyInfo != null;
            List<ValidationError>? errors = null;
            StringBuilder? keysAttempted = null;

            if (!keyMatched && validationParameters.TryAllIssuerSigningKeys && validationParameters.IssuerSigningKeys is not null)
            {
                // Control reaches here only if the key could not be resolved and TryAllIssuerSigningKeys is set to true.
                // We try all the keys in the list and return the first valid key. This is the degenerate case.
                for (int i = 0; i < validationParameters.IssuerSigningKeys.Count; i++)
                {
                    SecurityKey key = validationParameters.IssuerSigningKeys[i];
                    if (key is null)
                        continue;

                    var result = ValidateSignatureUsingKey(key, samlToken, validationParameters, callContext);
                    if (result.IsValid)
                        return result;

                    (errors ??= new()).Add(result.UnwrapError());

                    (keysAttempted ??= new()).Append(key.ToString());
                    if (canMatchKey && !keyMatched && key.KeyId is not null && samlToken.Assertion.Signature.KeyInfo is not null)
                        keyMatched = samlToken.Assertion.Signature.KeyInfo.MatchesKey(key);
                }
            }

            if (canMatchKey && keyMatched)
                return new XmlValidationError(
                    new MessageDetail(
                        TokenLogMessages.IDX10514,
                        keysAttempted?.ToString(),
                        samlToken.Assertion.Signature.KeyInfo,
                        GetErrorStrings(error, errors),
                        samlToken),
                    ValidationFailureType.SignatureValidationFailed,
                    typeof(SecurityTokenInvalidSignatureException),
                    ValidationError.GetCurrentStackFrame());

            string? keysAttemptedString = null;
            if (resolvedKey is not null)
                keysAttemptedString = resolvedKey.ToString();
            else if ((keysAttempted?.Length ?? 0) > 0)
                keysAttemptedString = keysAttempted!.ToString();

            if (keysAttemptedString is not null)
                return new XmlValidationError(
                    new MessageDetail(
                        TokenLogMessages.IDX10512,
                        keysAttemptedString,
                        GetErrorStrings(error, errors),
                        samlToken),
                    ValidationFailureType.SignatureValidationFailed,
                    typeof(SecurityTokenSignatureKeyNotFoundException),
                    ValidationError.GetCurrentStackFrame());

            return new XmlValidationError(
                new MessageDetail(TokenLogMessages.IDX10500),
                ValidationFailureType.SignatureValidationFailed,
                typeof(SecurityTokenSignatureKeyNotFoundException),
                ValidationError.GetCurrentStackFrame());
        }

        private static ValidationResult<SecurityKey> ValidateSignatureUsingKey(SecurityKey key, Saml2SecurityToken samlToken, ValidationParameters validationParameters, CallContext callContext)
        {
            ValidationResult<string> algorithmValidationResult = validationParameters.AlgorithmValidator(
                        samlToken.Assertion.Signature.SignedInfo.SignatureMethod,
                        key,
                        samlToken,
                        validationParameters,
                        callContext);

            if (!algorithmValidationResult.IsValid)
            {
                return algorithmValidationResult.UnwrapError().AddCurrentStackFrame();
            }
            else
            {
                var validationError = samlToken.Assertion.Signature.Verify(
                    key,
                    validationParameters.CryptoProviderFactory ?? key.CryptoProviderFactory,
                    callContext);

                if (validationError is null)
                {
                    samlToken.SigningKey = key;

                    return key;
                }
                else
                {
                    return validationError.AddCurrentStackFrame();
                }
            }
        }

        private static string GetErrorStrings(ValidationError? error, List<ValidationError>? errors)
        {
            // This method is called if there are errors in the signature validation process.
            // This check is there to account for the optional parameter.
            if (error is not null)
                return error.MessageDetail.Message;

            if (errors is null)
                return string.Empty;

            if (errors.Count == 1)
                return errors[0].MessageDetail.Message;

            StringBuilder sb = new();
            for (int i = 0; i < errors.Count; i++)
            {
                sb.AppendLine(errors[i].MessageDetail.Message);
            }

            return sb.ToString();
        }
    }
}
#nullable restore
