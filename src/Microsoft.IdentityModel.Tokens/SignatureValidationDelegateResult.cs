// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;

#nullable enable

namespace Microsoft.IdentityModel.Tokens
{
    /// <summary>
    /// Represents the result of a <see cref="SignatureValidatorWithToken"/> delegate invocation.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This type allows a signature validation delegate to indicate whether it handled the signature
    /// validation or whether it declined, allowing the handler to fall through to its default
    /// signature validation logic.
    /// </para>
    /// <para>
    /// Use <see cref="Success"/> when the delegate has validated the signature successfully.
    /// Use <see cref="NotHandled"/> when the delegate does not handle the token's algorithm and
    /// wants the handler to validate the signature using its built-in logic.
    /// If the delegate determines the signature is invalid, it should throw an appropriate exception
    /// (e.g., <see cref="SecurityTokenInvalidSignatureException"/>).
    /// </para>
    /// </remarks>
    public readonly struct SignatureValidationDelegateResult : IEquatable<SignatureValidationDelegateResult>
    {
        /// <summary>
        /// Gets a value indicating whether the delegate handled the signature validation.
        /// </summary>
        /// <value>
        /// <see langword="true"/> if the delegate validated the signature; <see langword="false"/>
        /// if the delegate declined and the handler should validate the signature using its default logic.
        /// </value>
        public bool Handled { get; }

        /// <summary>
        /// Gets the validated <see cref="SecurityToken"/> when <see cref="Handled"/> is <see langword="true"/>.
        /// </summary>
        /// <value>
        /// The validated token with <see cref="SecurityToken.SigningKey"/> set by the delegate,
        /// or <see langword="null"/> when <see cref="Handled"/> is <see langword="false"/>.
        /// </value>
        public SecurityToken? Token { get; }

        private SignatureValidationDelegateResult(SecurityToken token)
        {
            Handled = true;
            Token = token;
        }

        /// <summary>
        /// Returns a result indicating the delegate did not handle the signature validation.
        /// The handler will fall through to its default signature validation logic.
        /// </summary>
        public static SignatureValidationDelegateResult NotHandled => default;

        /// <summary>
        /// Returns a result indicating the delegate successfully validated the signature.
        /// </summary>
        /// <param name="token">The validated <see cref="SecurityToken"/> with
        /// <see cref="SecurityToken.SigningKey"/> set to the key used for validation.</param>
        /// <returns>A <see cref="SignatureValidationDelegateResult"/> indicating successful validation.</returns>
        /// <exception cref="ArgumentNullException">Thrown if <paramref name="token"/> is <see langword="null"/>.</exception>
        public static SignatureValidationDelegateResult Success(SecurityToken token)
            => new(token ?? throw new ArgumentNullException(nameof(token)));

        /// <inheritdoc/>
        public override bool Equals(object? obj) =>
            obj is SignatureValidationDelegateResult other && Equals(other);

        /// <inheritdoc/>
        public bool Equals(SignatureValidationDelegateResult other) =>
            Handled == other.Handled && ReferenceEquals(Token, other.Token);

        /// <inheritdoc/>
        public override int GetHashCode() =>
            Handled.GetHashCode() ^ (Token?.GetHashCode() ?? 0);

        /// <summary>Equality operator.</summary>
        public static bool operator ==(SignatureValidationDelegateResult left, SignatureValidationDelegateResult right) =>
            left.Equals(right);

        /// <summary>Inequality operator.</summary>
        public static bool operator !=(SignatureValidationDelegateResult left, SignatureValidationDelegateResult right) =>
            !left.Equals(right);
    }
}
