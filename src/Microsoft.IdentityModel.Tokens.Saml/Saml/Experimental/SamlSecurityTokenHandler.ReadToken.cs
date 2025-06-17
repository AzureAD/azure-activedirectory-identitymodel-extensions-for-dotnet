// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Text;
using System.Xml;
using Microsoft.Identity.Abstractions;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Tokens.Experimental;
using Microsoft.IdentityModel.Tokens.Saml.Experimental;
using TokenLogMessages = Microsoft.IdentityModel.Tokens.LogMessages;

namespace Microsoft.IdentityModel.Tokens.Saml
{
    public partial class SamlSecurityTokenHandler : SecurityTokenHandler
    {
        /// <summary>
        /// Converts a string into an instance of <see cref="SamlSecurityToken"/>.
        /// </summary>
        /// <param name="token">a Saml token as a string.</param>
        /// <param name="callContext">An opaque context used to store work when working with authentication artifacts.</param>
        /// <returns>A <see cref="SamlSecurityToken"/></returns>
        /// <exception cref="ArgumentNullException">If <paramref name="token"/> is null or empty.</exception>
        /// <exception cref="ArgumentException">If 'token.Length' is greater than <see cref="TokenHandler.MaximumTokenSizeInBytes"/>.</exception>
#pragma warning disable RS0051 // Add internal types and members to the declared API
        internal virtual OperationResult<SamlSecurityToken, ValidationError> ReadSamlToken(string token, CallContext callContext)
#pragma warning restore RS0051 // Add internal types and members to the declared API
        {
            if (string.IsNullOrEmpty(token))
                return ValidationError.NullParameter(
                    nameof(token),
                    ValidationError.GetCurrentStackFrame());

            if (token.Length > MaximumTokenSizeInBytes)
                return new ValidationError(
                    new MessageDetail(
                        TokenLogMessages.IDX10209,
                        LogHelper.MarkAsNonPII(token.Length),
                        LogHelper.MarkAsNonPII(MaximumTokenSizeInBytes)),
                    ValidationFailureType.TokenExceedsMaximumSize,
                    ValidationError.GetCurrentStackFrame());

            try
            {
                using (var reader = XmlDictionaryReader.CreateTextReader(Encoding.UTF8.GetBytes(token), XmlDictionaryReaderQuotas.Max))
                {
                    return ReadSamlToken(reader);
                }
            }
#pragma warning disable CA1031 // Do not catch general exception types
            catch (Exception ex)
#pragma warning restore CA1031 // Do not catch general exception types
            {
                return new SamlValidationError(
                    new MessageDetail(LogMessages.IDX11402, ex.Message),
                    ValidationFailureType.TokenReadingFailed,
                    ValidationError.GetCurrentStackFrame(),
                    ex);
            }
        }
    }
}
