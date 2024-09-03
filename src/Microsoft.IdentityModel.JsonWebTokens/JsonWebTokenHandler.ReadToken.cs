// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Diagnostics;
using Microsoft.IdentityModel.Tokens;

#nullable enable
namespace Microsoft.IdentityModel.JsonWebTokens
{
    /// <remarks>This partial class contains methods and logic related to the validation of tokens.</remarks>
    public partial class JsonWebTokenHandler : TokenHandler
    {
        /// <summary>
        /// Converts a string into an instance of <see cref="JsonWebToken"/>, returned inside of a <see cref="Result{TResult}"/>.
        /// </summary>
        /// <param name="token">A JSON Web Token (JWT) in JWS or JWE Compact Serialization format.</param>
        /// <param name="callContext"></param>
        /// <returns>A <see cref="Result{TResult}"/> with the <see cref="JsonWebToken"/> if valid, or an error.</returns>
        /// <exception cref="ArgumentNullException">returned if <paramref name="token"/> is null or empty.</exception>
        /// <exception cref="SecurityTokenMalformedException">returned if the validationParameters.TokenReader delegate is not able to parse/read the token as a valid <see cref="JsonWebToken"/>.</exception>
        /// <exception cref="SecurityTokenMalformedException">returned if <paramref name="token"/> is not a valid JWT, <see cref="JsonWebToken"/>.</exception>
        internal static Result<SecurityToken> ReadToken(
            string token,
#pragma warning disable CA1801 // TODO: remove pragma disable once callContext is used for logging
            CallContext? callContext)
#pragma warning disable CA1801 // TODO: remove pragma disable once callContext is used for logging
        {
            if (String.IsNullOrEmpty(token))
            {
                StackFrame nullTokenStackFrame = StackFrames.ReadTokenNullOrEmpty ?? new StackFrame(true);
                return ExceptionDetail.NullParameter(
                    nameof(token),
                    nullTokenStackFrame);
            }

            try
            {
                JsonWebToken jsonWebToken = new JsonWebToken(token);
                return jsonWebToken;
            }
#pragma warning disable CA1031 // Do not catch general exception types
            catch (Exception ex)
#pragma warning restore CA1031 // Do not catch general exception types
            {
                StackFrame malformedTokenStackFrame = StackFrames.ReadTokenMalformed ?? new StackFrame(true);
                return new ExceptionDetail(
                    new MessageDetail(LogMessages.IDX14107),
                    ValidationFailureType.TokenReadingFailed,
                    typeof(SecurityTokenMalformedException),
                    malformedTokenStackFrame,
                    ex);
            }
        }
    }
}
#nullable restore
