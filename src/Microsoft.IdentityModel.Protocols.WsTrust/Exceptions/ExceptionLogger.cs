// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

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
