// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Security.Claims;
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

        /// <summary>
        /// Called by base class to create a <see cref="ClaimsIdentity"/>.
        /// Currently only used by the JsonWebTokenHandler when called with ValidationParameters to allow for a Lazy creation.
        /// </summary>
        /// <param name="securityToken">the <see cref="SecurityToken"/> that has the Claims.</param>
        /// <param name="validationParameters">the <see cref="ValidationParameters"/> that was used to validate the token.</param>
        /// <param name="issuer">the 'issuer' to use by default when creating a Claim.</param>
        /// <returns>A <see cref="ClaimsIdentity"/>.</returns>
        /// <exception cref="NotImplementedException"></exception>
        internal virtual ClaimsIdentity CreateClaimsIdentityInternal(SecurityToken securityToken, ValidationParameters validationParameters, string issuer)
        {
            throw LogExceptionMessage(
                new NotImplementedException(
                    FormatInvariant(
                        LogMessages.IDX10267,
                        MarkAsNonPII("internal virtual ClaimsIdentity CreateClaimsIdentityInternal(SecurityToken securityToken, ValidationParameters validationParameters, string issuer)"),
                        MarkAsNonPII(GetType().FullName))));
        }
    }
}
