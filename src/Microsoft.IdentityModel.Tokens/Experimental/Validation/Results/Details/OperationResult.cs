// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;

#if NETCOREAPP
using System.Diagnostics.CodeAnalysis;
#endif

#nullable enable
#pragma warning disable RS0016 // Add public types and members to the declared API
namespace Microsoft.Identity.Abstractions
{
    /// <summary>
    /// Represents the result of an operation that can either succeed with a valid result or failed with a specific error.
    /// </summary>
    /// <typeparam name="TResult">The type of the successful result value.</typeparam>
    /// <typeparam name="TError">The type of the error.</typeparam>
    /// <remarks>
    /// This struct implements a discriminated union pattern for operation results.
    /// It ensures that either a valid result or an error is available, but never both.
    /// This pattern helps with clear error handling and propagation.
    /// </remarks>

    public readonly record struct OperationResult<TResult, TError>
            where TError : OperationError
    {
        /// <summary>
        /// Creates a new instance of <see cref="OperationResult{TResult, TError}"/> indicating a successful operation
        /// and containing an object of the associated type.
        /// </summary>
        /// <param name="result">The value associated with the success.</param>
        public OperationResult(TResult result)
        {
            Result = result;
            Error = default;
            Succeeded = true;
        }

        /// <summary>
        /// Creates a new instance of <see cref="OperationResult{TResult, TError}"/>
        /// indicating a failed operation and containing error information.
        /// </summary>
        /// <param name="error">The error associated with the failure.</param>
        public OperationResult(TError error)
        {
            Result = default;
            Error = error;
            Succeeded = false;
        }

        /// <summary>
        /// Empty constructor implementation to prevent creating an empty result.
        /// </summary>
        /// <remarks>Throws an <see cref="InvalidOperationException"/> when called as this should never be used. Always initialize Result with either a value or error.</remarks>
        /// <exception cref="InvalidOperationException">Thrown when called.</exception>
        [Obsolete("Cannot create an empty operation result", true)]
        public OperationResult() => throw new InvalidOperationException("Cannot create an empty operation result");

        /// <summary>
        /// Gets a value indicating whether the operation succeeded.
        /// </summary>
        /// <value>
        /// <c>true</c> if the operation succeeded and <see cref="Result"/> contains a valid value;
        /// <c>false</c> if the operation failed and <see cref="Error"/> contains the error.
        /// </value>
#if NETCOREAPP
        [MemberNotNullWhen(true, nameof(Result))]
        [MemberNotNullWhen(false, nameof(Error))]
#endif
        public readonly bool Succeeded { get; }

        /// <summary>
        /// Gets the error associated with the operation result.
        /// </summary>
        /// <returns>The error associated with the operation result.</returns>
        /// <remarks>This property is only valid if the result type is not valid.</remarks>
        public readonly TError? Error { get; }

        /// <summary>
        /// Gets the result associated with the operation result.
        /// </summary>
        /// <returns>The result associated with the operation result.</returns>
        /// <remarks>This property is only valid if the result type is valid.</remarks>
        public readonly TResult? Result { get; }

        /// <summary>
        /// Creates an <see cref="OperationResult{TResult, TError}"/>, successful result implicitly from the value.
        /// </summary>
        /// <param name="result">The value to be stored in the result.</param>
        public static implicit operator OperationResult<TResult, TError>(TResult result) => new(result);

        /// <summary>
        /// Creates an <see cref="OperationResult{TResult, TError}"/> result implicitly from the error value.
        /// </summary>
        /// <param name="error">The error to be stored in the result.</param>
        public static implicit operator OperationResult<TResult, TError>(TError error) => new(error);

        /// <summary>
        /// Casts the result to a <see cref="OperationResult{TResult, TError}"/>.
        /// </summary>#
        /// <remarks>Required for compatibility, see CA2225 for more information</remarks>
        /// <returns>The existing instance.</returns>
        public OperationResult<TResult, TError> ToOperationResult()
        {
            return this;
        }
    }
}
#pragma warning restore RS0016 // Add public types and members to the declared API
#nullable restore


