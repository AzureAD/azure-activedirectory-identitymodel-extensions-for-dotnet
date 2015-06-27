using System;
using System.Collections.Generic;

namespace Microsoft.IdentityModel.Tokens.Saml
{
    public class SamlAudienceRestrictionCondition : SamlCondition
    {
        public IList<Uri> Audiences { get; set; }
    }
}
