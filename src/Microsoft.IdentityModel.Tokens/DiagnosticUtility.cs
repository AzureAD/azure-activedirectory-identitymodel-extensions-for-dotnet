//------------------------------------------------------------------------------
//
// Copyright (c) Microsoft Corporation.
// All rights reserved.
//
// This code is licensed under the MIT License.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files(the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and / or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions :
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
//
//------------------------------------------------------------------------------

using System;

namespace Microsoft.IdentityModel.Tokens
{
    /// <summary>
    /// Provides common code for services to use in generating diagnostics and taking actions.
    /// </summary>
    public static class DiagnosticUtility
    {
        /// <summary>
        /// Returns true if the provided exception matches any of a list of hard system faults that should be allowed
        /// through to outer exception handlers.
        /// </summary>
        /// <param name="exception">The exception to check.</param>
        /// <remarks>
        /// <para>Typically this method is used when there is a need to catch all exceptions, but to ensure that .NET runtime
        /// and execution engine exceptions are not absorbed by the catch block. Use of this method also avoids FxCop
        /// warnings about not using general catch blocks.</para>
        /// <para>Please note that use of this method is expensive because of the amount of reflection it performs.
        /// If you can refactor your code to catch more specific exceptions than Exception to avoid using this method,
        /// you should.</para>
        /// <para>Example of use:</para>
        /// <code>
        /// try
        /// {
        ///     // Code needing a full Exception catch block
        /// }
        /// catch (Exception ex)
        /// {
        ///     if (DiagnosticUtility.IsFatal(ex))
        ///     {
        ///         throw;
        ///     }
        ///     // Perform any needed logging and handling for absorbed exception.
        /// }
        /// </code>
        /// </remarks>
        /// <returns>true if the exception should NOT be trapped</returns>
        public static bool IsFatal(Exception exception)
        {
            bool returnValue = false;

            if (exception is OutOfMemoryException ||
                exception is TypeInitializationException)
            {
                returnValue = true;
            }

            return returnValue;
        }
    }
}
