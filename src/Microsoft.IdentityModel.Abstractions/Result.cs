// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;

#nullable enable
namespace Microsoft.IdentityModel.Abstractions
{
    /// <summary>
    /// Represents a result that can be either successful or unsuccessful.
    /// </summary>
    /// <typeparam name="TResult"></typeparam>
    /// <typeparam name="TError"></typeparam>
    public readonly struct Result<TResult, TError> : IEquatable<Result<TResult, TError>>
    {
        readonly TResult? _result;
        readonly TError? _error;

        /// <summary>
        /// Creates a successful result.
        /// </summary>
        /// <param name="result">The value associated with the success.</param>
        public Result(TResult result)
        {
            _result = result;
            _error = default;
            IsSuccess = true;
        }

        /// <summary>
        /// Creates an error result.
        /// </summary>
        /// <param name="error">The error associated with the failure.</param>
        public Result(TError error)
        {
            _result = default;
            _error = error;
            IsSuccess = false;
        }

        /// <summary>
        /// Gets a value indicating whether the result is successful.
        /// </summary>
        readonly public bool IsSuccess { get; }

        /// <summary>
        /// Unwraps the result.
        /// </summary>
        /// <returns>The wrapped result value.</returns>
        /// <remarks>This method is only valid if the result type is successful.</remarks>
        /// <exception cref="InvalidOperationException">Thrown if attempted to unwrap the value from a failed result.</exception>
        public TResult Unwrap() => IsSuccess ? _result! : throw new InvalidOperationException("Cannot unwrap error result");

        /// <summary>
        /// Unwraps the error.
        /// </summary>
        /// <returns>The wrapped error value.</returns>
        /// <remarks>This method is only valid if the result type is unsuccessful.</remarks>
        /// <exception cref="InvalidOperationException">Thrown if attempted to unwrap an error from a successful result.</exception>
        public TError UnwrapError() => IsSuccess ? throw new InvalidOperationException("Cannot unwrap success result") : _error!;

        /// <summary>
        /// 
        /// </summary>
        /// <param name="obj"></param>
        /// <returns></returns>
        public override bool Equals(object? obj)
        {
            if (obj is Result<TResult, TError> other)
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
            {
                return _result!.GetHashCode();
            }
            else
            {
                return _error!.GetHashCode();
            }
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="left"></param>
        /// <param name="right"></param>
        /// <returns></returns>
        public static bool operator ==(Result<TResult, TError> left, Result<TResult, TError> right)
        {
            return left.Equals(right);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="left"></param>
        /// <param name="right"></param>
        /// <returns></returns>
        public static bool operator !=(Result<TResult, TError> left, Result<TResult, TError> right)
        {
            return !(left == right);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="other"></param>
        /// <returns></returns>
        public bool Equals(Result<TResult, TError> other)
        {
            if (other.IsSuccess != IsSuccess)
                return false;

            if (IsSuccess)
                return _result!.Equals(other._result);
            else
                return _error!.Equals(other._error);
        }
    }
}
#nullable restore
