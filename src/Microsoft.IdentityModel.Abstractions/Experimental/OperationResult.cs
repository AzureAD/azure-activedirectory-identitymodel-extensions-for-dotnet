// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#if NETCOREAPP
using System.Diagnostics.CodeAnalysis;
#endif

#nullable enable
namespace Microsoft.IdentityModel.Abstractions.Experimental
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
#pragma warning disable RS0016 // Add public types and members to the declared API
    public readonly record struct OperationResult<TResult, TError>
#pragma warning restore RS0016 // Add public types and members to the declared API
            where TResult : class
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
            IsValid = true;
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
            IsValid = false;
        }

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
        public readonly bool IsValid { get; }

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
    }
}
#nullable restore
