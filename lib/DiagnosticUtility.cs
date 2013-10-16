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

namespace System.IdentityModel
{
    using System.Reflection;
    using System.Runtime.InteropServices;

    /// <summary>
    /// Provides common code for services to use in generating diagnostics and taking actions.
    /// </summary>
    internal static class DiagnosticUtility
    {
        /// <summary>
        /// Returns true if the provided exception matches any of a list of hard system faults that should be allowed
        /// through to outer exception handlers.
        /// </summary>
        /// <param name="exception"></param>
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

            if ((exception is OutOfMemoryException && !(exception is InsufficientMemoryException)) ||                
                exception is AccessViolationException ||
                exception is SEHException ||
                exception is TypeInitializationException ||
                exception is TargetInvocationException)
            {
                returnValue = true;
            }

            return returnValue;
        }
    }
}
