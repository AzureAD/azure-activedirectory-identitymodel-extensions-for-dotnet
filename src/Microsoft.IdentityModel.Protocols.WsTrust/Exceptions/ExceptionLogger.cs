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
using Microsoft.IdentityModel.Logging;

namespace Microsoft.IdentityModel.Protocols.WsTrust
{
    /// <summary>
    /// Helper class for logging.
    /// </summary>
    internal class ExceptionLogger
    {
        /// <summary>
        /// Logs an exception using the event source logger and returns new <see cref="WsTrustReadException"/> exception.
        /// </summary>
        /// <param name="message">message for exception.</param>
        /// <remarks>EventLevel is set to Error.</remarks>
        internal static Exception LogWsTrustReadException(string message)
        {
            return LogHelper.LogExceptionMessage(new WsTrustReadException(message));
        }

        /// <summary>
        /// Logs an exception using the event source logger and returns new <see cref="WsTrustReadException"/> exception.
        /// </summary>
        /// <param name="message">message for exception.</param>
        /// <param name="innerException">inner exceptioin.</param>
        /// <remarks>EventLevel is set to Error.</remarks>
        internal static Exception LogWsTrustReadException(string message, Exception innerException)
        {
            return LogHelper.LogExceptionMessage(new WsTrustReadException(message, innerException));
        }

        /// <summary>
        /// Logs an exception using the event source logger and returns new <see cref="WsTrustReadException"/> exception.
        /// </summary>
        /// <param name="format">argument that is null or empty.</param>
        /// <param name="args">arguments for formatting</param>
        /// <remarks>EventLevel is set to Error.</remarks>
        internal static Exception LogWsTrustReadException(string format, params object[] args)
        {
            return LogHelper.LogExceptionMessage(new WsTrustReadException(LogHelper.FormatInvariant(format, args)));
        }

        /// <summary>
        /// Logs an exception using the event source logger and returns new typed exception.
        /// </summary>
        /// <param name="innerException">the inner <see cref="Exception"/> to be added to the outer exception.</param>
        /// <param name="format">Format string of the log message.</param>
        /// <param name="args">An object array that contains zero or more objects to format.</param>
        internal static Exception LogWsTrustReadException(Exception innerException, string format, params object[] args)
        {
            return LogHelper.LogExceptionMessage(new WsTrustReadException(LogHelper.FormatInvariant(format, args), innerException));
        }
    }
}
