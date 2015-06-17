using System;
using System.Collections.Generic;

namespace Microsoft.IdentityModel.Tokens.Saml2
{
    public class Saml2Conditions
    {
        public DateTime? NotBefore
        {
            get; set;
        }

        public DateTime? Expires
        {
            get; set;
        }

        public IList<Saml2AudienceRestriction> AudienceRestrictions { get; set; }
    }
}
