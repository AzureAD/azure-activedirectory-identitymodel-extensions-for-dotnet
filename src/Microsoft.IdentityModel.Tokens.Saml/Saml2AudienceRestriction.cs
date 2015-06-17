using System;
using System.Collections.Generic;

namespace Microsoft.IdentityModel.Tokens.Saml2
{
    public class Saml2AudienceRestriction
    {
        public IList<Uri> Audiences { get; set; }
    }
}
