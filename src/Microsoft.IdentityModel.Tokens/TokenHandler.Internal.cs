// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Tokens.Experimental;
using static Microsoft.IdentityModel.Logging.LogHelper;

namespace Microsoft.IdentityModel.Tokens
{
    /// <summary>
    /// Defines properties shared across all security token handlers.
    /// </summary>
    public abstract partial class TokenHandler
    {
        internal virtual Task<ValidationResult<ValidatedToken, ValidationError>> ValidateTokenAsync(
            string token,
            ValidationParameters validationParameters,
            CallContext callContext,
            CancellationToken cancellationToken)
        {
            throw LogExceptionMessage(
                new NotImplementedException(
                    FormatInvariant(
                        LogMessages.IDX10267,
                        MarkAsNonPII("internal virtual Task<ValidationResult<ValidatedToken, ValidationError>> " +
                        "ValidateTokenAsync(string token, ValidationParameters validationParameters, CallContext callContext, CancellationToken cancellationToken)"),
                        MarkAsNonPII(GetType().FullName))));
        }

        internal virtual Task<ValidationResult<ValidatedToken, ValidationError>> ValidateTokenAsync(
            SecurityToken token,
            ValidationParameters validationParameters,
            CallContext callContext,
            CancellationToken cancellationToken)
        {
            throw LogExceptionMessage(
                new NotImplementedException(
                    FormatInvariant(
                        LogMessages.IDX10267,
                        MarkAsNonPII("internal virtual Task<ValidationResult<ValidatedToken, ValidationError>> " +
                        "ValidateTokenAsync(SecurityToken token, ValidationParameters validationParameters, CallContext callContext, CancellationToken cancellationToken)"),
                        MarkAsNonPII(GetType().FullName))));
        }
    }
}
