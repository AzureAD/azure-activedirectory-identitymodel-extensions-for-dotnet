// ----------------------------------------------------------------------------------
//
// Copyright Microsoft Corporation
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
// ----------------------------------------------------------------------------------

using System.Diagnostics;
using System.Globalization;
using System.Reflection;

namespace System.IdentityModel
{
    /// <summary>
    /// Provides common code for services to use in generating diagnostics and taking actions.
    /// </summary>
    internal static class DiagnosticUtility
    {
        /// <summary>
        /// Provides a basic assertion facility to output stack trace details to trace, and in a debug build
        /// to additionally print a message to the console and invoke <see cref="System.Environment.FailFast(string)"/>.
        /// </summary>
        public static void Assert(bool condition, string message)
        {            
            if (!condition)
            {
                message = string.Format(CultureInfo.InvariantCulture, "{0}: {1}", message, new StackTrace().ToString());
#if DEBUG
                Console.WriteLine(message);
                Environment.FailFast(message);
#endif
            }
        }

        /// <summary>
        /// Provides a basic assertion facility to output stack trace details to trace, and in a debug build
        /// to additionally print a message to the console and invoke <see cref="System.Environment.FailFast(string)"/>.
        /// </summary>
        public static void Assert(bool condition, string format, params object[] args)
        {
            if (!condition)
            {
                string message = string.Format(CultureInfo.InvariantCulture, format, args);
#if DEBUG
                Console.WriteLine(message);
                Environment.FailFast(message);
#endif
            }
        }

        /// <summary>
        /// Returns true if the provided exception matches any of a list of hard system faults that should be allowed
        /// through to outer exception handlers.
        /// </summary>
        /// <remarks>
        /// <para>Typically this method is used when there is a need to catch all exceptions, but to ensure that .NET runtime
        /// and execution engine exceptions are not absorbed by the catch block. Use of this method also avoids FxCop
        /// warnings about not using general catch blocks.</para>
        ///
        /// <para>Please note that use of this method is expensive because of the amount of reflection it performs.
        /// If you can refactor your code to catch more specific exceptions than Exception to avoid using this method,
        /// you should.</para>
        ///
        /// <para>Example of use:</para>
        ///
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
        public static bool IsFatal(Exception exception)
        {
            bool returnValue = false;

            if ((exception is OutOfMemoryException && !(exception is InsufficientMemoryException)) ||                
                exception is AccessViolationException ||
                exception is System.Runtime.InteropServices.SEHException ||
                exception is TypeInitializationException ||
                exception is TargetInvocationException)
            {
                returnValue = true;
            }

            return returnValue;
        }

        /// <summary>
        /// Prints the message to the console, then executes <see cref="System.Environment.FailFast(string)"/>.
        /// </summary>
        public static void FailFast(string message)
        {
            message = string.Format(CultureInfo.InvariantCulture, "{0}: {1}", message, new StackTrace().ToString());
            Environment.FailFast(message);
        }

        public static void FailFastIfFatal(Exception exception)
        {
            if (DiagnosticUtility.IsFatal(exception))
            {
                DiagnosticUtility.FailFast(exception.Message);
            }
        }
    }
}
