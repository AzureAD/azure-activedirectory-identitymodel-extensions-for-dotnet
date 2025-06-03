// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using Microsoft.Extensions.Logging;

namespace Microsoft.IdentityModel.Tokens
{
    /// <summary>
    /// Extensions for <see cref="TokenValidationParameters"/>.
    /// </summary>
    [CLSCompliant(false)]
    public static class TokenValidationParametersExtensions
    {
        internal static string s_callContextKey = typeof(TokenValidationParameters).FullName + ".CallContext";

        /// <summary>
        /// Adds the provided <see cref="ILogger"/> to the <see cref="TokenValidationParameters"/>.
        /// </summary>
        /// <param name="validationParameters">The <see cref="TokenValidationParameters"/> instance.</param>
        /// <param name="logger">The <see cref="ILogger"/> to use.</param>
        public static void SetLogger(this TokenValidationParameters validationParameters, ILogger logger)
        {
            if (validationParameters == null)
                throw new ArgumentNullException(nameof(validationParameters));

            if (logger == null)
                throw new ArgumentNullException(nameof(logger));

            validationParameters.InstancePropertyBag[s_callContextKey] = new CallContext(logger);
        }

        /// <summary>
        /// Retrieves the <see cref="CallContext"/> from <see cref="TokenValidationParameters"/>.
        /// </summary>
        /// <param name="validationParameters"></param>
        /// <returns>A <see cref="CallContext"/></returns>
        internal static CallContext GetCallContext(this TokenValidationParameters validationParameters)
        {
            if (validationParameters == null)
                return null;

            if (validationParameters.InstancePropertyBag.TryGetValue(s_callContextKey, out var obj) && obj is CallContext callContext)
                return callContext;

            return null;
        }
    }
}
