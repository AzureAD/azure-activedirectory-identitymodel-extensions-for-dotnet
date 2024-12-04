// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

namespace Microsoft.IdentityModel.Tokens
{
    /// <summary>
    /// The type of the failure that occurred when validating a <see cref="SecurityToken"/>.
    /// </summary>
    internal abstract class ValidationFailureType
    {
        /// <summary>
        /// Creates an instance of <see cref="TokenValidationResult"/>
        /// </summary>
        protected ValidationFailureType(string name)
        {
            Name = name;
        }

        /// <summary>
        /// Gets the name of the <see cref="ValidationFailureType"/>.
        /// </summary>
        public string Name { get; }

        /// <summary>
        /// Defines a type that represents a required parameter was null.
        /// </summary>
        public static readonly ValidationFailureType NullArgument = new NullArgumentFailure("NullArgument");
        private class NullArgumentFailure : ValidationFailureType { internal NullArgumentFailure(string name) : base(name) { } }

        /// <summary>
        /// Defines a type that represents that issuer validation failed.
        /// </summary>
        public static readonly ValidationFailureType IssuerValidationFailed = new IssuerValidationFailure("IssuerValidationFailed");
        private class IssuerValidationFailure : ValidationFailureType { internal IssuerValidationFailure(string name) : base(name) { } }

        /// <summary>
        /// Defines a type that represents an algorithm validation failed.
        /// </summary>
        public static readonly ValidationFailureType AlgorithmValidationFailed = new AlgorithmValidationFailure("AlgorithmValidationFailed");
        private class AlgorithmValidationFailure : ValidationFailureType { internal AlgorithmValidationFailure(string name) : base(name) { } }

        /// <summary>
        /// Defines a type that represents that audience validation failed.
        /// </summary>
        public static readonly ValidationFailureType AudienceValidationFailed = new AudienceValidationFailure("AudienceValidationFailed");
        private class AudienceValidationFailure : ValidationFailureType { internal AudienceValidationFailure(string name) : base(name) { } }

        /// <summary>
        /// Defines a type that represents that audience validation failed.
        /// </summary>
        public static readonly ValidationFailureType NoTokenAudiencesProvided = new NoTokenAudiencesProvidedFailure("NoTokenAudiencesProvided");
        private class NoTokenAudiencesProvidedFailure : ValidationFailureType { internal NoTokenAudiencesProvidedFailure(string name) : base(name) { } }

        /// <summary>
        /// Defines a type that represents that audience validation failed.
        /// </summary>
        public static readonly ValidationFailureType NoValidationParameterAudiencesProvided = new NoValidationParameterAudiencesProvidedFailure("NoValidationParameterAudiencesProvided");
        private class NoValidationParameterAudiencesProvidedFailure : ValidationFailureType { internal NoValidationParameterAudiencesProvidedFailure(string name) : base(name) { } }

        /// <summary>
        /// Defines a type that represents that token type validation failed.
        /// </summary>
        public static readonly ValidationFailureType TokenTypeValidationFailed = new TokenTypeValidationFailure("TokenTypeValidationFailed");
        private class TokenTypeValidationFailure : ValidationFailureType { internal TokenTypeValidationFailure(string name) : base(name) { } }

        /// <summary>
        /// Defines a type that represents that the token's signature validation failed.
        /// </summary>
        public static readonly ValidationFailureType SignatureValidationFailed = new SignatureValidationFailure("SignatureValidationFailed");
        private class SignatureValidationFailure : ValidationFailureType { internal SignatureValidationFailure(string name) : base(name) { } }

        /// <summary>
        /// Defines a type that represents that the token is not signed.
        /// </summary>
        public static readonly ValidationFailureType TokenIsNotSigned = new TokenNotSignedFailure("TokenIsNotSigned");
        private class TokenNotSignedFailure : ValidationFailureType { internal TokenNotSignedFailure(string name) : base(name) { } }

        /// <summary>
        /// Defines a type that represents that the token's signature algorithm validation failed.
        /// </summary>
        public static readonly ValidationFailureType SignatureAlgorithmValidationFailed = new SignatureAlgorithmValidationFailure("SignatureAlgorithmValidationFailed");
        private class SignatureAlgorithmValidationFailure : ValidationFailureType { internal SignatureAlgorithmValidationFailure(string name) : base(name) { } }

        /// <summary>
        /// Defines a type that represents that signing key validation failed.
        /// </summary>
        public static readonly ValidationFailureType SigningKeyValidationFailed = new IssuerSigningKeyValidationFailure("IssuerSigningKeyValidationFailed");
        private class IssuerSigningKeyValidationFailure : ValidationFailureType { internal IssuerSigningKeyValidationFailure(string name) : base(name) { } }

        /// <summary>
        /// Defines a type that represents that lifetime validation failed.
        /// </summary>
        public static readonly ValidationFailureType LifetimeValidationFailed = new LifetimeValidationFailure("LifetimeValidationFailed");
        private class LifetimeValidationFailure : ValidationFailureType { internal LifetimeValidationFailure(string name) : base(name) { } }

        /// <summary>
        /// Defines a type that represents that token replay validation failed.
        /// </summary>
        public static readonly ValidationFailureType TokenReplayValidationFailed = new TokenReplayValidationFailure("TokenReplayValidationFailed");
        private class TokenReplayValidationFailure : ValidationFailureType { internal TokenReplayValidationFailure(string name) : base(name) { } }

        /// <summary>
        /// Defines a type that represents that a token could not be read.
        /// </summary>
        public static readonly ValidationFailureType TokenReadingFailed = new TokenReadingFailure("TokenReadingFailed");
        private class TokenReadingFailure : ValidationFailureType { internal TokenReadingFailure(string name) : base(name) { } }

        /// <summary>
        /// Defines a type that represents that a token exceeds the maximum size.
        /// </summary>
        public static readonly ValidationFailureType TokenExceedsMaximumSize = new TokenExceedsMaximumSizeFailure("TokenExceedsMaximumSize");
        private class TokenExceedsMaximumSizeFailure : ValidationFailureType { internal TokenExceedsMaximumSizeFailure(string name) : base(name) { } }

        /// <summary>
        /// Defines a type that represents that a JWE could not be decrypted.
        /// </summary>
        public static readonly ValidationFailureType TokenDecryptionFailed = new TokenDecryptionFailure("TokenDecryptionFailed");
        private class TokenDecryptionFailure : ValidationFailureType { internal TokenDecryptionFailure(string name) : base(name) { } }

        /// <summary>
        /// Defines a type that represents that a token is invalid.
        /// </summary>
        public static readonly ValidationFailureType InvalidSecurityToken = new InvalidSecurityTokenFailure("InvalidSecurityToken");
        private class InvalidSecurityTokenFailure : ValidationFailureType { internal InvalidSecurityTokenFailure(string name) : base(name) { } }

        /// <summary>
        /// Defines a type that represents that an XML validation failed.
        /// </summary>
        public static readonly ValidationFailureType XmlValidationFailed = new XmlValidationFailure("XmlValidationFailed");
        private class XmlValidationFailure : ValidationFailureType { internal XmlValidationFailure(string name) : base(name) { } }

        /// <summary>
        /// Defines a type that represents the fact that the algorithm validation delegate threw an exception.
        /// </summary>
        public static readonly ValidationFailureType AlgorithmValidatorThrew = new AlgorithmValidationFailure("AlgorithmValidatorThrew");

        /// <summary>
        /// Defines a type that represents the fact that the issuer validation delegate threw an exception.
        /// </summary>
        public static readonly ValidationFailureType IssuerValidatorThrew = new IssuerValidatorFailure("IssuerValidatorThrew");
        private class IssuerValidatorFailure : ValidationFailureType { internal IssuerValidatorFailure(string name) : base(name) { } }

        /// <summary>
        /// Defines a type that represents the fact that the issuer signing key validation delegate threw an exception.
        /// </summary>
        public static readonly ValidationFailureType IssuerSigningKeyValidatorThrew = new IssuerSigningKeyValidationFailure("IssuerSigningKeyValidatorThrew");

        /// <summary>
        /// Defines a type that represents the fact that the signature validation delegate threw an exception.
        /// </summary>
        public static readonly ValidationFailureType SignatureValidatorThrew = new SignatureValidationFailure("SignatureValidatorThrew");

        /// <summary>
        /// Defines a type that represents the fact that the token replay validation delegate threw an exception.
        /// </summary>
        public static readonly ValidationFailureType TokenReplayValidatorThrew = new TokenReplayValidationFailure("TokenReplayValidatorThrew");

        /// <summary>
        /// Defines a type that represents the fact that the token type validation delegate threw an exception.
        /// </summary>
        public static readonly ValidationFailureType TokenTypeValidatorThrew = new TokenTypeValidationFailure("TokenTypeValidatorThrew");
    }
}
