// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;

#nullable enable
namespace Microsoft.IdentityModel.Tokens
{
    /// <summary>
    /// Represents a validation result that can be either successful or unsuccessful.
    /// </summary>
    /// <typeparam name="TResult"></typeparam>
    internal readonly struct ValidationResult<TResult> : IEquatable<ValidationResult<TResult>>
    {
        readonly TResult? _result;
        readonly ValidationError? _error;

        /// <summary>
        /// Creates a successful validation result.
        /// </summary>
        /// <param name="result">The value associated with the success.</param>
        public ValidationResult(TResult result)
        {
            _result = result;
            _error = null;
            IsSuccess = true;
        }

        /// <summary>
        /// Creates an error validation result.
        /// </summary>
        /// <param name="error">The error associated with the failure.</param>
        public ValidationResult(ValidationError error)
        {
            _result = default;
            _error = error;
            IsSuccess = false;
        }

        /// <summary>
        /// Empty constructor implementation to prevent creating an empty result.
        /// </summary>
        /// <remarks>Throws an <see cref="InvalidOperationException"/> when called as this should never be used. Always initialize Result with either a value or error.</remarks>
        /// <exception cref="InvalidOperationException">Thrown when called.</exception>
        [Obsolete("Cannot create an empty validation result", true)]
        public ValidationResult() => throw new InvalidOperationException("Cannot create an empty validation result");

        /// <summary>
        /// Creates a successful result implicitly from the value.
        /// </summary>
        /// <param name="result">The value to be stored in the result.</param>
        public static implicit operator ValidationResult<TResult>(TResult result) => new(result);

        /// <summary>
        /// Creates an error result implicitly from the error value.
        /// </summary>
        /// <param name="error">The error to be stored in the result.</param>
        public static implicit operator ValidationResult<TResult>(ValidationError error) => new(error);

        /// <summary>
        /// Gets a value indicating whether the result is successful.
        /// </summary>
        public readonly bool IsSuccess { get; }

        /// <summary>
        /// Unwraps the result.
        /// </summary>
        /// <returns>The wrapped result value.</returns>
        /// <remarks>This method is only valid if the result type is successful.</remarks>
        /// <exception cref="InvalidOperationException">Thrown if attempted to unwrap the value from a failed result.</exception>
        public TResult UnwrapResult() => IsSuccess ? _result! : throw new InvalidOperationException("Cannot unwrap error result");

        /// <summary>
        /// Unwraps the error.
        /// </summary>
        /// <returns>The wrapped error value.</returns>
        /// <remarks>This method is only valid if the result type is unsuccessful.</remarks>
        /// <exception cref="InvalidOperationException">Thrown if attempted to unwrap an error from a successful result.</exception>
        public ValidationError UnwrapError() => IsSuccess ? throw new InvalidOperationException("Cannot unwrap success result") : _error!;

        /// <summary>
        /// 
        /// </summary>
        /// <param name="obj"></param>
        /// <returns></returns>
        public override bool Equals(object? obj)
        {
            if (obj is ValidationResult<TResult> other)
            {
                return Equals(other);
            }

            return false;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <returns></returns>
        /// <exception cref="NotImplementedException"></exception>
        public override int GetHashCode()
        {
            if (IsSuccess)
                return _result!.GetHashCode();
            else
                return _error!.GetHashCode();
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="left"></param>
        /// <param name="right"></param>
        /// <returns></returns>
        public static bool operator ==(ValidationResult<TResult> left, ValidationResult<TResult> right)
        {
            return left.Equals(right);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="left"></param>
        /// <param name="right"></param>
        /// <returns></returns>
        public static bool operator !=(ValidationResult<TResult> left, ValidationResult<TResult> right)
        {
            return !(left == right);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="other"></param>
        /// <returns></returns>
        public bool Equals(ValidationResult<TResult> other)
        {
            if (other.IsSuccess != IsSuccess)
                return false;

            if (IsSuccess)
                return _result!.Equals(other._result);
            else
                return _error!.Equals(other._error);
        }

        /// <summary>
        /// Casts the result to a <see cref="ValidationResult{TResult}"/>.
        /// </summary>#
        /// <remarks>Required for compatibility, see CA2225 for more information</remarks>
        /// <returns>The existing instance.</returns>
        public ValidationResult<TResult> ToResult()
        {
            return this;
        }
    }
}
#nullable restore
