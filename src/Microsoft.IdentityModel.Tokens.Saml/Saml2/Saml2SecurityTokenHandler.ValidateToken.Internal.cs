﻿// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Abstractions;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Tokens.Saml;
using static Microsoft.IdentityModel.Logging.LogHelper;

using TokenLogMessages = Microsoft.IdentityModel.Tokens.LogMessages;

#nullable enable
namespace Microsoft.IdentityModel.Tokens.Saml2
{
    public partial class Saml2SecurityTokenHandler : SecurityTokenHandler
    {
        /// <inheritdoc/>
        internal async Task<ValidationResult<ValidatedToken>> ValidateTokenAsync(
            string token,
            ValidationParameters validationParameters,
            CallContext callContext,
            CancellationToken cancellationToken)
        {
            if (string.IsNullOrEmpty(token))
            {
                StackFrame nullTokenStackFrame = StackFrames.TokenStringNull ??= new StackFrame(true);
                return ValidationError.NullParameter(
                        nameof(token),
                        nullTokenStackFrame);
            }

            if (validationParameters is null)
            {
                StackFrame nullValidationParametersStackFrame = StackFrames.TokenStringValidationParametersNull ??= new StackFrame(true);
                return ValidationError.NullParameter(
                        nameof(validationParameters),
                        nullValidationParametersStackFrame);
            }

            if (token.Length > MaximumTokenSizeInBytes)
            {
                StackFrame invalidTokenLengthStackFrame = StackFrames.InvalidTokenLength ??= new StackFrame(true);
                return new ValidationError(
                        new MessageDetail(
                            TokenLogMessages.IDX10209,
                            LogHelper.MarkAsNonPII(token.Length),
                            LogHelper.MarkAsNonPII(MaximumTokenSizeInBytes)),
                        ValidationFailureType.InvalidSecurityToken,
                        typeof(ArgumentException),
                        invalidTokenLengthStackFrame);
            }

            //NOTE: do we want to update SAML such that it can understand configuration manager?
            validationParameters = await SamlTokenUtilities.PopulateValidationParametersWithCurrentConfigurationAsync(validationParameters).ConfigureAwait(false);

            ValidationResult<ValidatedToken> signatureValidationResult = ValidateSignature(token, validationParameters, callContext, cancellationToken);
            ValidatedToken samlToken = signatureValidationResult.UnwrapResult();

            if (samlToken == null)
            {
                throw LogExceptionMessage(
                    new SecurityTokenValidationException(
                        FormatInvariant(
                            TokenLogMessages.IDX10254,
                            LogHelper.MarkAsNonPII(_className),
                            LogHelper.MarkAsNonPII("ValidateToken"),
                            LogHelper.MarkAsNonPII(_className),
                            LogHelper.MarkAsNonPII("ValidateSignature"),
                            LogHelper.MarkAsNonPII(typeof(Saml2SecurityToken)))));
            }

            //NOTE: Why do we do this?
            /*        var claimsPrincipal = ValidateToken(samlToken, token, validationParameters, out var validatedToken); 
                    return new TokenValidationResult
                    {
                        SecurityToken = validatedToken,
                        ClaimsIdentity = claimsPrincipal?.Identities.First(),
                        IsValid = true,
                    };*/

            StackFrame mockTokenStackFrame = StackFrames.TokenStringNull ??= new StackFrame(true); // TODO: fix this, not the right stack frame
            return ValidationError.NullParameter(nameof(token), mockTokenStackFrame); //TODO: fix this, not the right return value
        }

        internal static ValidationResult<ValidatedToken> ValidateSignature(string token, ValidationParameters validationParameters, CallContext callContext, CancellationToken cancellationToken)
        {
            if (string.IsNullOrWhiteSpace(token))
            {
                throw LogArgumentNullException(nameof(token));
            }

            if (validationParameters == null)
            {
                throw LogArgumentNullException(nameof(validationParameters));
            }

            //TODO: We need to figure out how will the new validationParameters.SignatureValidator delegate work together with JsonWebTokenHandler and SAML2TokenHandler
            /*            if (validationParameters.SignatureValidator != null)
                        {
                            validationParameters.SignatureValidator(jwtToken, validationParameters, configuration, callContext);
                            var validatedSamlToken = validationParameters.SignatureValidator(token, validationParameters, validationParameters.ConfigurationManager., cancellationToken);
                            if (validatedSamlToken == null)
                                throw LogExceptionMessage(new SecurityTokenValidationException(FormatInvariant(TokenLogMessages.IDX10505, token)));

                            if (!(validatedSamlToken is Saml2SecurityToken validatedSaml))
                                throw LogExceptionMessage(new SecurityTokenValidationException(FormatInvariant(TokenLogMessages.IDX10506, LogHelper.MarkAsNonPII(typeof(Saml2SecurityToken)), LogHelper.MarkAsNonPII(validatedSamlToken.GetType()), token)));

                            return validatedSaml;
            }*/

            var samlToken = ReadSaml2Token(token);
            if (samlToken == null)
                throw LogExceptionMessage(
                    new SecurityTokenValidationException(FormatInvariant(TokenLogMessages.IDX10254, LogHelper.MarkAsNonPII(_className), LogHelper.MarkAsNonPII("ValidateSignature"), LogHelper.MarkAsNonPII(_className), LogHelper.MarkAsNonPII("ReadSaml2Token"), LogHelper.MarkAsNonPII(typeof(Saml2SecurityToken)))));

            return ValidateSignatureAsync(samlToken, token, validationParameters, callContext, cancellationToken);
        }

        private async ValueTask<ValidationResult<ValidatedToken>> ValidateSignatureAsync(Saml2SecurityToken samlToken, string token, ValidationParameters validationParameters, CallContext callContext, CancellationToken cancellationToken)
        {
            //TODO: Check if we need to re-include this check in VP?
            /*            if (samlToken.Assertion.Signature == null)
                            if (validationParameters.RequireSignedTokens)
                                throw LogExceptionMessage(new SecurityTokenValidationException(FormatInvariant(TokenLogMessages.IDX10504, token)));
                            else
                                return samlToken;*/

            bool keyMatched = false;
            IEnumerable<SecurityKey>? keys = null;

            //NOTE: This delegate is still in TBD state will need to re-add this check once a direction is decided.
            /*            if (validationParameters.IssuerSigningKeyResolver != null)
                        {
                            keys = validationParameters.IssuerSigningKeyResolver(token, samlToken, samlToken.Assertion.Signature.KeyInfo?.Id, validationParameters);
                        }*/

            var singleKey = ResolveIssuerSigningKey(token, samlToken, validationParameters);
            if (singleKey != null)
            {
                // remember that key was matched for throwing exception SecurityTokenSignatureKeyNotFoundException
                keyMatched = true;
                keys = [singleKey];
            }

            if (keys == null && validationParameters.TryAllIssuerSigningKeys)
            {
                // control gets here if:
                // 1. User specified delegate: IssuerSigningKeyResolver returned null
                // 2. ResolveIssuerSigningKey returned null
                // Try all the keys. This is the degenerate case, not concerned about perf.
                keys = TokenUtilities.GetAllSigningKeys(validationParameters: validationParameters);
            }

            // keep track of exceptions thrown, keys that were tried
            var exceptionStrings = new StringBuilder();
            var keysAttempted = new StringBuilder();
            bool canMatchKey = samlToken.Assertion.Signature.KeyInfo != null;

            if (keys != null)
            {
                foreach (var key in keys)
                {
                    try
                    {
                        //TODO: Re-enable this once we migrate ValidateAlgorithm to the new model
                        //Validators.ValidateAlgorithm(samlToken.Assertion.Signature.SignedInfo.SignatureMethod, key, samlToken, validationParameters);

                        samlToken.Assertion.Signature.Verify(key, validationParameters.CryptoProviderFactory ?? key.CryptoProviderFactory);

                        if (LogHelper.IsEnabled(EventLogLevel.Informational))
                            LogHelper.LogInformation(TokenLogMessages.IDX10242, token);

                        samlToken.SigningKey = key;
                        return new ValidationResult<ValidatedToken>(new ValidatedToken(samlToken));
                    }
#pragma warning disable CA1031 // Do not catch general exception types
                    catch (Exception ex)
                    {
                        exceptionStrings.AppendLine(ex.ToString());
                    }
#pragma warning restore CA1031 // Do not catch general exception types

                    if (key != null)
                    {
                        keysAttempted.Append(key.ToString()).Append(" , KeyId: ").AppendLine(key.KeyId);
                        if (canMatchKey && !keyMatched && key.KeyId != null)
                            keyMatched = samlToken.Assertion.Signature.KeyInfo!.MatchesKey(key);
                    }
                }
            }

            if (canMatchKey)
            {
                if (keyMatched)
                    throw LogHelper.LogExceptionMessage(new SecurityTokenInvalidSignatureException(LogHelper.FormatInvariant(TokenLogMessages.IDX10514, keysAttempted, samlToken.Assertion.Signature.KeyInfo, exceptionStrings, samlToken)));

                //TODO: Re-enable this once we migrate ValidateIssuer to the new model
                //ValidateIssuer(samlToken.Issuer, samlToken, validationParameters);
                ValidationResult<ValidatedToken> validationResult = await ValidateConditions(samlToken, validationParameters, callContext).ConfigureAwait(false);
            }

            if (keysAttempted.Length > 0)
                throw LogExceptionMessage(new SecurityTokenSignatureKeyNotFoundException(FormatInvariant(TokenLogMessages.IDX10512, keysAttempted, exceptionStrings, samlToken)));

            throw LogHelper.LogExceptionMessage(new SecurityTokenSignatureKeyNotFoundException(TokenLogMessages.IDX10500));
        }

        internal virtual SecurityKey ResolveIssuerSigningKey(string token, Saml2SecurityToken samlToken, ValidationParameters validationParameters)
        {
            if (samlToken == null)
                throw LogArgumentNullException(nameof(samlToken));

            if (validationParameters == null)
                throw LogArgumentNullException(nameof(validationParameters));

            if (samlToken.Assertion == null)
                throw LogArgumentNullException(nameof(samlToken.Assertion));

            return SamlTokenUtilities.ResolveTokenSigningKey(samlToken.Assertion.Signature.KeyInfo, validationParameters);
        }

        internal ValueTask<ValidationResult<ValidatedToken>> ValidateConditionsAsync(Saml2SecurityToken samlToken, ValidationParameters validationParameters, CallContext callContext)
        {
            if (samlToken == null)
                throw LogArgumentNullException(nameof(samlToken));

            if (validationParameters == null)
                throw LogArgumentNullException(nameof(validationParameters));

            if (samlToken.Assertion == null)
                throw LogArgumentNullException(nameof(samlToken.Assertion));


            //TODO: Check if we still need this?
            /*        if (samlToken.Assertion.Conditions == null)
                    {
                        if (validationParameters.RequireAudience)
                            throw LogExceptionMessage(new Saml2SecurityTokenException(LogMessages.IDX13002));

                        return;
                    }*/

            //TODO: Re-enable lifetime validation once we point to the new delegates.
            //ValidateLifetime(samlToken.Assertion.Conditions.NotBefore, samlToken.Assertion.Conditions.NotOnOrAfter, samlToken, validationParameters);

            //TODO: Check why do we need this?
            /*        if (samlToken.Assertion.Conditions.OneTimeUse)
                        ValidateOneTimeUseCondition(samlToken, validationParameters);*/

            if (samlToken.Assertion.Conditions.ProxyRestriction != null)
                throw LogExceptionMessage(new SecurityTokenValidationException(LogMessages.IDX13511));

            var foundAudienceRestriction = false;
            foreach (var audienceRestriction in samlToken.Assertion.Conditions.AudienceRestrictions)
            {
                if (!foundAudienceRestriction)
                    foundAudienceRestriction = true;

                ValidationResult<string> audienceResultValidation = ValidateAudience((IList<string>)audienceRestriction.Audiences, samlToken, validationParameters, callContext);
            }

            if (!foundAudienceRestriction)
                throw LogExceptionMessage(new Saml2SecurityTokenException(LogMessages.IDX13002));
        }

        internal static ValidationResult<string> ValidateAudience(IList<string> audiences, SecurityToken securityToken, ValidationParameters validationParameters, CallContext callContext)
        {
            return Validators.ValidateAudience(audiences, securityToken, validationParameters, callContext);
        }
    }
}
#nullable restore
