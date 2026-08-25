// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens.Experimental;

namespace Microsoft.IdentityModel.Tokens;

/// <summary>
/// Extensions for <see cref="ValidationParameters"/>.
/// </summary>
[CLSCompliant(false)]
public static class ValidationParametersExtensions
{
    internal static string s_callContextKey = typeof(ValidationParameters).FullName + ".CallContext";

    /// <summary>
    /// Adds the provided <see cref="ILogger"/> to the <see cref="ValidationParameters"/>.
    /// </summary>
    /// <param name="validationParameters">The <see cref="ValidationParameters"/> instance.</param>
    /// <param name="logger">The <see cref="ILogger"/> to use.</param>
    public static void SetLogger(this ValidationParameters validationParameters, ILogger logger)
    {
        if (validationParameters == null)
            throw new ArgumentNullException(nameof(validationParameters));

        if (logger == null)
            throw new ArgumentNullException(nameof(logger));

        validationParameters.InstancePropertyBag[s_callContextKey] = new CallContext(logger);
    }

    /// <summary>
    /// Retrieves the <see cref="CallContext"/> from <see cref="ValidationParameters"/>.
    /// </summary>
    /// <param name="validationParameters"></param>
    /// <returns>A <see cref="CallContext"/></returns>
    internal static CallContext GetCallContext(this ValidationParameters validationParameters)
    {
        if (validationParameters == null)
            return null;

        if (validationParameters.InstancePropertyBag.TryGetValue(s_callContextKey, out object obj) && obj is CallContext callContext)
            return callContext;

        return null;
    }
}
