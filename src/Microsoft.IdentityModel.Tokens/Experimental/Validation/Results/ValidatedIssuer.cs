// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#nullable enable
namespace Microsoft.IdentityModel.Tokens.Experimental
{
    /// <summary>
    /// Represents a validated issuer, including the source of the validation.
    /// </summary>
    public class ValidatedIssuer
    {
        /// <summary>
        /// Initializes a new instance of <see cref="ValidatedIssuer"/>.
        /// </summary>
        /// <param name="issuer">The issuer that was validated.</param>
        /// <param name="validationSource">The source of the validation, i.e. configuration, validation parameters.</param>
        public ValidatedIssuer(string issuer, IssuerValidationSource validationSource)
        {
            Issuer = issuer;
            ValidationSource = validationSource;
        }

        /// <summary>
        /// The issuer that was validated.
        /// </summary>
        public string Issuer { get; }

        /// <summary>
        /// The source of the validation, i.e. configuration, validation parameters.
        /// </summary>
        public IssuerValidationSource ValidationSource { get; }

        /// <summary>
        /// The validated issuer's string representation.
        /// </summary>
        /// <returns>A string representing the issuer and where it was validated from.</returns>
        public override string ToString() => $"{Issuer} (from {ValidationSource})";
    }
}
#nullable restore
