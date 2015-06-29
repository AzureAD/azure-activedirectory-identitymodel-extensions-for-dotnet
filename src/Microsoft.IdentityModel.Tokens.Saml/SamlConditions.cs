using System;
using System.Collections.Generic;

namespace Microsoft.IdentityModel.Tokens.Saml
{
    public class SamlConditions
    {
        public DateTime? NotBefore
        {
            get; set;
        }

        public DateTime? Expires
        {
            get; set;
        }

        public IList<SamlCondition> Conditions { get; set; }
    }
}
