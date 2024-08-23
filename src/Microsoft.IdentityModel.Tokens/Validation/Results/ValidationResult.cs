// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#nullable enable
using System;
using System.Diagnostics;

namespace Microsoft.IdentityModel.Tokens
{
    /// <summary>
    /// Contains results of a single step in validating a <see cref="SecurityToken"/>.
    /// A <see cref="TokenValidationResult"/> maintains a list of <see cref="ValidationResult"/> for each step in the token validation.
    /// </summary>
    internal class ValidationResult
    {
        /// <summary>
        /// Creates an instance of <see cref="ValidationResult"/>
        /// </summary>
        /// <param name="securityToken">The <see cref="SecurityToken"/> that is being validated.</param>
        /// <param name="tokenHandler">The <see cref="TokenHandler"/> that is being used to validate the token.</param>
        /// <param name="validationParameters">The <see cref="ValidationParameters"/> to be used for validating the token.</param>
        internal ValidationResult(
            SecurityToken securityToken,
            TokenHandler tokenHandler,
            ValidationParameters validationParameters)
        {
            TokenHandler = tokenHandler ?? throw new ArgumentNullException("TokenHandler cannot be null.");
            SecurityToken = securityToken;
            ValidationParameters = validationParameters;
            IsValid = true;
        }

        public ValidationResult(
            SecurityToken? securityToken,
            TokenHandler tokenHandler,
            ValidationParameters? validationParameters,
            ExceptionDetail exceptionDetail,
            StackFrame? stackFrame = null)
        {
            TokenHandler = tokenHandler ?? throw new ArgumentNullException("TokenHandler cannot be null.");
            SecurityToken = securityToken;
            ValidationParameters = validationParameters;
            ExceptionDetail = exceptionDetail;
            IsValid = false;

            if (stackFrame != null)
                ExceptionDetail.StackFrames.Add(stackFrame);
        }

        public ExceptionDetail? ExceptionDetail { get; private set; }

        /// <summary>
        /// True if the token was successfully validated, false otherwise.
        /// </summary>
        public bool IsValid { get; private set; }

        /// <summary>
        /// Logs the validation result.
        /// </summary>
#pragma warning disable CA1822 // Mark members as static
        public void Log()
#pragma warning restore CA1822 // Mark members as static
        {
            // TODO - Do we need this, how will it work?
        }

        public SecurityToken? SecurityToken { get; private set; }

        public TokenHandler TokenHandler { get; private set; }

        public ValidationParameters? ValidationParameters { get; private set; }

        #region Validation Results
        public ValidationResult? ActorValidationResult { get; internal set; }
        public string? ValidatedAudience { get; internal set; }
        public ValidatedIssuer ValidatedIssuer { get; internal set; }
        public ValidatedLifetime? ValidatedLifetime { get; internal set; }
        public DateTime? ValidatedTokenReplayExpirationTime { get; internal set; }
        public ValidatedTokenType? ValidatedTokenType { get; internal set; }
        public SecurityKey? ValidatedSigningKey { get; internal set; }
        public ValidatedSigningKeyLifetime? ValidatedSigningKeyLifetime { get; internal set; }
        #endregion

    }
}
#nullable disable
