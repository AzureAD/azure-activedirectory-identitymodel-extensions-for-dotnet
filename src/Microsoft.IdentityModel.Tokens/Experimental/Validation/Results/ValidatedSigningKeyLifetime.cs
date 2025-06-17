// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;

#nullable enable
namespace Microsoft.IdentityModel.Tokens.Experimental
{
    /// <summary>
    /// Represents a validated signing key lifetime.
    /// </summary>
    public class ValidatedSigningKeyLifetime
    {
        /// <summary>
        /// Initializes a new instance of <see cref="ValidatedSigningKeyLifetime"/>.
        /// </summary>
        /// <param name="notBefore">The <see cref="DateTime"/> representing the time from which the signing key is considered valid.</param>
        /// <param name="expires">The <see cref="DateTime"/> representing the the signing key expiration time.</param>
        /// <param name="validationTime">The time the validation occurred.</param>
        internal ValidatedSigningKeyLifetime(DateTime? notBefore, DateTime? expires, DateTime? validationTime)
        {
            NotBefore = notBefore;
            Expires = expires;
            ValidationTime = validationTime;
        }

        /// <summary>
        /// The <see cref="DateTime"/> representing the time from which the the signing key is considered valid.
        /// </summary>
        public DateTime? NotBefore { get; }

        /// <summary>
        /// The <see cref="DateTime"/> representing the the signing key expiration time.
        /// </summary>
        public DateTime? Expires { get; }

        /// <summary>
        /// The time the validation occurred.
        /// </summary>
        public DateTime? ValidationTime { get; }

        /// <summary>
        /// The validated signing key lifetime's string representation.
        /// </summary>
        /// <returns>A string that represents the validated signing key lifetime and the validation time.</returns>
        public override string ToString() => $"{ValidationTime} ∊ [{NotBefore}, {Expires}]";
    }
}
#nullable restore
