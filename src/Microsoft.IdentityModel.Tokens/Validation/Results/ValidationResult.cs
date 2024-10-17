// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using Microsoft.IdentityModel.Logging;

#nullable enable
namespace Microsoft.IdentityModel.Tokens
{
    /// <summary>
    /// Represents a validation result that can be either valid or invalid.
    /// </summary>
    /// <typeparam name="TResult"></typeparam>
    internal readonly struct ValidationResult<TResult> : IEquatable<ValidationResult<TResult>>
    {
        readonly TResult? _result;
        readonly ValidationError? _error;

        /// <summary>
        /// Creates a successful, valid validation result.
        /// </summary>
        /// <param name="result">The value associated with the success.</param>
        public ValidationResult(TResult result)
        {
            _result = result;
            _error = null;
            IsValid = true;
        }

        /// <summary>
        /// Creates an error, invalid validation result.
        /// </summary>
        /// <param name="error">The error associated with the failure.</param>
        public ValidationResult(ValidationError error)
        {
            _result = default;
            _error = error;
            IsValid = false;
        }

        /// <summary>
        /// Empty constructor implementation to prevent creating an empty result.
        /// </summary>
        /// <remarks>Throws an <see cref="InvalidOperationException"/> when called as this should never be used. Always initialize Result with either a value or error.</remarks>
        /// <exception cref="InvalidOperationException">Thrown when called.</exception>
        [Obsolete("Cannot create an empty validation result", true)]
        public ValidationResult() => throw new InvalidOperationException("Cannot create an empty validation result");

        /// <summary>
        /// Creates a successful, valid result implicitly from the value.
        /// </summary>
        /// <param name="result">The value to be stored in the result.</param>
        public static implicit operator ValidationResult<TResult>(TResult result) => new(result);

        /// <summary>
        /// Creates an error result implicitly from the error value.
        /// </summary>
        /// <param name="error">The error to be stored in the result.</param>
        public static implicit operator ValidationResult<TResult>(ValidationError error) => new(error);

        /// <summary>
        /// Gets a value indicating whether the result is valid.
        /// </summary>
        public readonly bool IsValid { get; }

        /// <summary>
        /// Unwraps the result.
        /// </summary>
        /// <returns>The wrapped result value.</returns>
        /// <remarks>This method is only valid if the result type is valid.</remarks>
        /// <exception cref="InvalidOperationException">Thrown if attempted to unwrap the value from a non valid result.</exception>
        internal TResult UnwrapResult() => IsValid ? _result! : throw new InvalidOperationException("Cannot unwrap error result");

        /// <summary>
        /// Unwraps the error.
        /// </summary>
        /// <returns>The wrapped error value.</returns>
        /// <remarks>This method is only valid if the result type is not valid.</remarks>
        /// <exception cref="InvalidOperationException">Thrown if attempted to unwrap an error from a valid result.</exception>
        internal ValidationError UnwrapError() => IsValid ? throw new InvalidOperationException("Cannot unwrap success result") : _error!;

        /// <summary>
        /// Gets the error associated with the validation result.
        /// </summary>
        /// <returns>The error associated with the validation result.</returns>
        /// <remarks>This property is only valid if the result type is not valid.</remarks>
        public ValidationError? Error
        {
            get
            {
                if (IsValid)
                    LogHelper.LogWarning("Warning: Accessing the Error property in a valid result is invalid.");

                return _error;
            }
        }

        /// <summary>
        /// Gets the result associated with the validation result.
        /// </summary>
        /// <returns>The result associated with the validation result.</returns>
        /// <remarks>This property is only valid if the result type is valid.</remarks>
        public TResult? Result
        {
            get
            {
                if (IsValid)
                    return _result;
                else
                {
                    LogHelper.LogWarning("Warning: Accessing the Result property in an invalid result may yield unexpected results.");
                    return default;
                }
            }
        }

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
            if (IsValid)
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
            if (other.IsValid != IsValid)
                return false;

            if (IsValid)
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
