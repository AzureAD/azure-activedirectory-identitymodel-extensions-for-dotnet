// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Linq;
using Microsoft.Identity.Abstractions;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Tokens.Experimental;

#nullable enable
namespace Microsoft.IdentityModel.Tokens
{
    /// <summary>
    /// Partial class for Algorithm Validation.
    /// </summary>
    public static partial class Validators
    {
        /// <summary>
        /// Validates a given algorithm for a <see cref="SecurityKey"/>.
        /// </summary>
        /// <param name="algorithm">The algorithm to be validated.</param>
        /// <param name="securityKey">The <see cref="SecurityKey"/> that signed the <see cref="SecurityToken"/>.</param>
        /// <param name="securityToken">The <see cref="SecurityToken"/> being validated.</param>
        /// <param name="validationParameters"><see cref="ValidationParameters"/> required for validation.</param>
        /// <param name="callContext">The <see cref="CallContext"/> that contains call information.</param>
#pragma warning disable RS0016 // Add public types and members to the declared API
        public static OperationResult<string, ValidationError> ValidateAlgorithm(
#pragma warning restore RS0016 // Add public types and members to the declared API
            string algorithm,
#pragma warning disable CA1801
            SecurityKey securityKey,
            SecurityToken securityToken,
            ValidationParameters validationParameters,
            CallContext callContext)
#pragma warning restore CA1801
        {
            if (validationParameters == null)
                return new AlgorithmValidationError(
                    MessageDetail.NullParameter(nameof(validationParameters)),
                    ValidationFailureType.NullArgument,
                    ValidationError.GetCurrentStackFrame(),
                    algorithm,
                    null);

            if (validationParameters.ValidAlgorithms != null &&
                validationParameters.ValidAlgorithms.Count > 0 &&
                !validationParameters.ValidAlgorithms.Contains(algorithm, StringComparer.Ordinal))
                return new AlgorithmValidationError(
                    new MessageDetail(
                        LogMessages.IDX10696,
                        LogHelper.MarkAsNonPII(algorithm)),
                    ValidationFailureType.InvalidAlgorithm,
                    ValidationError.GetCurrentStackFrame(),
                    algorithm,
                    null);

            return algorithm;
        }
    }
}
#nullable restore
