// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;

#nullable enable
namespace Microsoft.IdentityModel.Tokens.Experimental
{
    /// <summary>
    /// Represents a validated lifetime, including the NotBefore and Expires values.
    /// </summary>
    public class ValidatedLifetime
    {
        /// <summary>
        /// Initializes a new instance of <see cref="ValidatedLifetime"/>.
        /// </summary>
        /// <param name="notBefore">The <see cref="DateTime"/> representing the time from which the token is considered valid.</param>
        /// <param name="expires">The <see cref="DateTime"/> representing the token's expiration time.</param>
        public ValidatedLifetime(DateTime? notBefore, DateTime? expires)
        {
            NotBefore = notBefore;
            Expires = expires;
        }

        /// <summary>
        /// The <see cref="DateTime"/> representing the time from which the token is considered valid.
        /// </summary>
        public DateTime? NotBefore { get; }

        /// <summary>
        /// The <see cref="DateTime"/> representing the token's expiration time.
        /// </summary>
        public DateTime? Expires { get; }

        /// <summary>
        /// The validated lifetime's string representation.
        /// </summary>
        /// <returns>A string representing the validated lifetime.</returns>
        public override string ToString() => $"[{NotBefore}, {Expires}]";
    }
}
#nullable restore
