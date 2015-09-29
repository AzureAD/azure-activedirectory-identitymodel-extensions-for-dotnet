//-----------------------------------------------------------------------
// Copyright (c) Microsoft Open Technologies, Inc.
// All Rights Reserved
// Apache License 2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//-----------------------------------------------------------------------

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
