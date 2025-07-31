// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Text;
using System.Xml;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Tokens.Experimental;

namespace Microsoft.IdentityModel.Tokens.Saml
{
    public partial class SamlSecurityTokenHandler : SecurityTokenHandler
    {
        /// <summary>
        /// Converts a string into an instance of <see cref="SamlSecurityToken"/>, returned inside of a <see cref="ValidationResult{SecurityToken, ValidationError}"/>.
        /// </summary>
        /// <param name="token">A Saml token as a string.</param>
        /// <param name="serializer">A <see cref="SamlSerializer"/> that is used to read the string.</param>
        /// <param name="callContext">A <see cref="CallContext"/> that contains call information.</param>
        /// <returns>A <see cref="ValidationResult{SecurityToken, ValidationError}"/> with the <see cref="SamlSecurityToken"/> or a <see cref="ValidationError"/>.</returns>
        internal static ValidationResult<SecurityToken, ValidationError> ReadToken(
            string token,
            SamlSerializer serializer,
#pragma warning disable CA1801 // Remove unused parameter
            CallContext callContext)
#pragma warning restore CA1801 // Remove unused parameter
        {
            if (string.IsNullOrEmpty(token))
                return ValidationError.NullParameter(
                    nameof(token),
                    ValidationError.GetCurrentStackFrame());

            try
            {
                using (var reader = XmlDictionaryReader.CreateTextReader(Encoding.UTF8.GetBytes(token), XmlDictionaryReaderQuotas.Max))
                {
                    var assertion = serializer.ReadAssertion(reader);
                    if (assertion == null)
                        return new ValidationError(
                            new MessageDetail(LogMessages.IDX11138, LogHelper.MarkAsNonPII(serializer.GetType())),
                            ValidationFailureType.TokenReadingFailed,
                            ValidationError.GetCurrentStackFrame());

                    return new SamlSecurityToken(assertion);
                }
            }
#pragma warning disable CA1031 // Do not catch general exception types
            catch (Exception ex)
#pragma warning restore CA1031 // Do not catch general exception types
            {
                return new ValidationError(
                    new MessageDetail(LogMessages.IDX11402, ex.Message),
                    ValidationFailureType.TokenReadingFailed,
                    ValidationError.GetCurrentStackFrame(),
                    ex);
            }
        }
    }
}
