// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Text;
using System.Xml;
using Microsoft.Identity.Abstractions;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Tokens.Experimental;

namespace Microsoft.IdentityModel.Tokens.Saml2
{
    public partial class Saml2SecurityTokenHandler : SecurityTokenHandler
    {
        /// <summary>
        /// Converts a string into an instance of <see cref="Saml2SecurityToken"/>, returned inside of a <see cref="OperationResult{SecurityToken, ValidationError}"/>.
        /// </summary>
        /// <param name="token">A JSON Web Token (JWT) in JWS or JWE Compact Serialization format.</param>
        /// <param name="serializer"></param>
        /// <param name="callContext"></param>
        /// <returns>A <see cref="OperationResult{SecurityToken, ValidationError}"/> with the <see cref="Saml2SecurityToken"/> or a <see cref="ValidationError"/>.</returns>
#pragma warning disable CA1801 // Review unused parameters
        internal static OperationResult<SecurityToken, ValidationError> ReadToken(
            string token,
            Saml2Serializer serializer,
            CallContext callContext)
#pragma warning restore CA1801 // Review unused parameters
        {
            if (string.IsNullOrEmpty(token))
                return ValidationError.NullParameter(nameof(token), ValidationError.GetCurrentStackFrame());

            try
            {
                using (var reader = XmlDictionaryReader.CreateTextReader(Encoding.UTF8.GetBytes(token), XmlDictionaryReaderQuotas.Max))
                {
                    var assertion = serializer.ReadAssertion(reader);
                    if (assertion == null)
                        return new ValidationError(
                            new MessageDetail(LogMessages.IDX13315, LogHelper.MarkAsNonPII(serializer.GetType())),
                            ValidationFailureType.TokenReadingFailed,
                            ValidationError.GetCurrentStackFrame());

                    return new Saml2SecurityToken(assertion);
                }
            }
#pragma warning disable CA1031 // Do not catch general exception types
            catch (Exception ex)
#pragma warning restore CA1031 // Do not catch general exception types
            {
                return new ValidationError(
                    new MessageDetail(LogMessages.IDX13003, ex.Message),
                    ValidationFailureType.TokenReadingFailed,
                    ValidationError.GetCurrentStackFrame(),
                    ex);
            }
        }
    }
}
