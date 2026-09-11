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
public static class TokenValidationParametersExtensions
{
    internal static string s_callContextKey = typeof(TokenValidationParameters).FullName + ".CallContext";

    /// <summary>
    /// Adds the provided <see cref="ILogger"/> to the <see cref="TokenValidationParameters"/>.
    /// </summary>
    /// <param name="tokenValidationParameters">The <see cref="TokenValidationParameters"/> instance.</param>
    /// <param name="logger">The <see cref="ILogger"/> to use.</param>
    public static void SetLogger(this TokenValidationParameters tokenValidationParameters, ILogger logger)
    {
        if (tokenValidationParameters == null)
            throw new ArgumentNullException(nameof(tokenValidationParameters));

        if (logger == null)
            throw new ArgumentNullException(nameof(logger));

        tokenValidationParameters.InstancePropertyBag[s_callContextKey] = new CallContext(logger);
    }

    /// <summary>
    /// Retrieves the <see cref="CallContext"/> from <see cref="TokenValidationParameters"/>.
    /// </summary>
    /// <param name="tokenValidationParameters"></param>
    /// <returns>A <see cref="CallContext"/></returns>
    internal static CallContext GetCallContext(this TokenValidationParameters tokenValidationParameters)
    {
        if (tokenValidationParameters == null)
            return null;

        if (tokenValidationParameters.InstancePropertyBag.TryGetValue(s_callContextKey, out object obj) && obj is CallContext callContext)
            return callContext;

        return null;
    }
}
