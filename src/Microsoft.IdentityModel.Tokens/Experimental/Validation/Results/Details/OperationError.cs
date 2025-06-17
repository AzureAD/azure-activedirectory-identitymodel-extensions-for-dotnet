// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

namespace Microsoft.Identity.Abstractions
{
    /// <summary>
    /// Represents an error that occurred during an operation.
    /// </summary>
#pragma warning disable RS0016 // Add public types and members to the declared API
    public abstract class OperationError
    {
        /// <summary>
        /// Creates an instance of <see cref="OperationError"/>
        /// </summary>
        protected OperationError()
        {
        }
    }
#pragma warning restore RS0016
}
