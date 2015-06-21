using System;

namespace Microsoft.IdentityModel.Tokens.Saml
{
    public class SamlConditions
    {
        public DateTime? NotBefore
        {
            get; set;
        }

        DateTime? Expires
        {
            get; set;
        }
    }
}
