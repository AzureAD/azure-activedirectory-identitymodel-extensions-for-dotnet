// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System.Collections.Generic;

#nullable enable
namespace Microsoft.IdentityModel.Tokens.Saml2
{
    /// <summary>
    /// A <see cref="SecurityTokenHandler"/> designed for creating and validating Saml2 Tokens. See: http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf
    /// </summary>
    public partial class Saml2SecurityTokenHandler : SecurityTokenHandler
    {
        /// <summary>
        /// Determines if the audience found in a <see cref="Saml2SecurityToken"/> is valid.
        /// </summary>
        /// <param name="audiences">The audiences found in the <see cref="Saml2SecurityToken"/></param>
        /// <param name="securityToken">The <see cref="Saml2SecurityToken"/> that is being validated.</param>
        /// <param name="validationParameters">The <see cref="ValidationParameters"/> to be used for validating the token.</param>
        /// <param name="callContext"></param>
        /// <remarks><see cref="Validators.ValidateAudience(IList{string}, SecurityToken, ValidationParameters, CallContext)"/> for additional details.</remarks>
        internal static ValidationResult<string> ValidateAudience(IList<string> audiences, SecurityToken securityToken, ValidationParameters validationParameters, CallContext callContext)
        {
            return Validators.ValidateAudience(audiences, securityToken, validationParameters, callContext);
        }
    }
}
#nullable restore
