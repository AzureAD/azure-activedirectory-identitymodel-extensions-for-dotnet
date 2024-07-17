// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Tokens;
using TokenLogMessages = Microsoft.IdentityModel.Tokens.LogMessages;

namespace Microsoft.IdentityModel.JsonWebTokens
{
    /// <summary>
    /// Definition for the delegate that converts a string into an instance of <see cref="JsonWebToken"/>.
    /// </summary>
    /// <param name="token">A JSON Web Token (JWT) in JWS or JWE Compact Serialization format.</param>
    /// <param name="callContext"></param>
    /// <returns>A <see cref="TokenReadingResult"/>that contains the results of reading the token.</returns>
    /// <remarks>This delegate is not expected to throw.</remarks>
    internal delegate TokenReadingResult TokenReadingDelegate(
        string token,
        CallContext callContext);

    /// <remarks>This partial class contains methods and logic related to the validation of tokens.</remarks>
    public partial class JsonWebTokenHandler : TokenHandler
    {
        /// <summary>
        /// Converts a string into an instance of <see cref="JsonWebToken"/>.
        /// </summary>
        /// <param name="token">A JSON Web Token (JWT) in JWS or JWE Compact Serialization format.</param>
        /// <param name="validationParameters">A <see cref="TokenValidationParameters"/> whose TokenReader, if set, will be used to read a JWT.</param>
        /// <returns>A <see cref="TokenValidationResult"/>.</returns>
        /// <exception cref="SecurityTokenMalformedException">Thrown if the validationParameters.TokenReader delegate is not able to parse/read the token as a valid <see cref="JsonWebToken"/>.</exception>
        /// <exception cref="SecurityTokenMalformedException">Thrown if <paramref name="token"/> is not a valid JWT, <see cref="JsonWebToken"/>.</exception>
        private static TokenValidationResult ReadToken(string token, TokenValidationParameters validationParameters)
        {
            JsonWebToken jsonWebToken = null;
            if (validationParameters.TokenReader != null)
            {
                var securityToken = validationParameters.TokenReader(token, validationParameters);
                if (securityToken == null)
                    throw LogHelper.LogExceptionMessage(new SecurityTokenMalformedException(LogHelper.FormatInvariant(TokenLogMessages.IDX10510, LogHelper.MarkAsSecurityArtifact(token, JwtTokenUtilities.SafeLogJwtToken))));

                jsonWebToken = securityToken as JsonWebToken;
                if (jsonWebToken == null)
                    throw LogHelper.LogExceptionMessage(new SecurityTokenMalformedException(LogHelper.FormatInvariant(TokenLogMessages.IDX10509, typeof(JsonWebToken), securityToken.GetType(), LogHelper.MarkAsSecurityArtifact(token, JwtTokenUtilities.SafeLogJwtToken))));
            }
            else
            {
#pragma warning disable CA1031 // Do not catch general exception types
                try
                {
                    jsonWebToken = new JsonWebToken(token);
                }
                catch (Exception ex)
                {
                    return new TokenValidationResult
                    {
                        Exception = ex,
                        IsValid = false
                    };
                }
#pragma warning restore CA1031 // Do not catch general exception types
            }

            return new TokenValidationResult
            {
                SecurityToken = jsonWebToken,
                IsValid = true
            };
        }

#nullable enable
        /// <summary>
        /// Converts a string into an instance of <see cref="JsonWebToken"/>, returned inside of a <see cref="TokenReadingResult"/>.
        /// </summary>
        /// <param name="token">A JSON Web Token (JWT) in JWS or JWE Compact Serialization format.</param>
        /// <param name="callContext"></param>
        /// <returns>A <see cref="TokenReadingResult"/> with the <see cref="JsonWebToken"/> if valid, or an Exception.</returns>
        /// <exception cref="ArgumentNullException">returned if <paramref name="token"/> is null or empty.</exception>
        /// <exception cref="SecurityTokenMalformedException">returned if the validationParameters.TokenReader delegate is not able to parse/read the token as a valid <see cref="JsonWebToken"/>.</exception>
        /// <exception cref="SecurityTokenMalformedException">returned if <paramref name="token"/> is not a valid JWT, <see cref="JsonWebToken"/>.</exception>
        internal static TokenReadingResult ReadToken(
            string token,
#pragma warning disable CA1801 // TODO: remove pragma disable once callContext is used for logging
            CallContext? callContext)
#pragma warning disable CA1801 // TODO: remove pragma disable once callContext is used for logging
        {
            if (String.IsNullOrEmpty(token))
            {
                return new TokenReadingResult(
                    token,
                    ValidationFailureType.NullArgument,
                    new ExceptionDetail(
                        new MessageDetail(
                            TokenLogMessages.IDX10000,
                            LogHelper.MarkAsNonPII(nameof(token))),
                        typeof(ArgumentNullException),
                        new System.Diagnostics.StackFrame()));
            }

            try
            {
                JsonWebToken jsonWebToken = new JsonWebToken(token);
                return new TokenReadingResult(jsonWebToken, token);
            }
#pragma warning disable CA1031 // Do not catch general exception types
            catch (Exception ex)
#pragma warning restore CA1031 // Do not catch general exception types
            {
                return new TokenReadingResult(
                    token,
                    ValidationFailureType.TokenReadingFailed,
                    new ExceptionDetail(
                        new MessageDetail(LogMessages.IDX14107),
                        ex.GetType(),
                        new System.Diagnostics.StackFrame(),
                        ex));
            }
        }
    }
}
#nullable restore
