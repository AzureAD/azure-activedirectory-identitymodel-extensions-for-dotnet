// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Text;
using System.Xml;
using Microsoft.IdentityModel.Logging;
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
        internal virtual ValidationResult<SamlSecurityToken> ReadSamlToken(string token, CallContext callContext)
        {
            if (string.IsNullOrEmpty(token))
                return ValidationError.NullParameter(nameof(token), ValidationError.GetCurrentStackFrame());

            if (token.Length > MaximumTokenSizeInBytes)
                return new ValidationError(
                        new MessageDetail(
                            TokenLogMessages.IDX10209,
                            LogHelper.MarkAsNonPII(token.Length),
                            LogHelper.MarkAsNonPII(MaximumTokenSizeInBytes)),
                        ValidationFailureType.TokenExceedsMaximumSize,
                        typeof(ArgumentOutOfRangeException),
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
                    typeof(SamlSecurityTokenReadException),
                    ValidationError.GetCurrentStackFrame(),
                    ex);
            }
        }
    }
}
