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
using System.Diagnostics.Tracing;

namespace Microsoft.IdentityModel.Logging
{
    /// <summary>
    /// Helper class for logging.
    /// </summary>
    public class LogHelper
    {
        /// <summary>
        /// Logs an event using the event source logger and throws the exception.
        /// </summary>
        /// <param name="message">message to log.</param>
        /// <param name="exceptionType">Type of the exception to be thrown.</param>
        /// <param name="logLevel">Identifies the level of an event to be logged. Default is Error.</param>
        /// <param name="innerException">the inner <see cref="Exception"/> to be added to the outer exception.</param>
        public static void Throw(string message, Type exceptionType, EventLevel logLevel = EventLevel.Error, Exception innerException = null)
        {
            IdentityModelEventSource.Logger.Write(logLevel, message, innerException);

            if (innerException != null)
                throw (Exception)Activator.CreateInstance(exceptionType, message, innerException);
            else
                throw (Exception)Activator.CreateInstance(exceptionType, message);
        }
    }
}
