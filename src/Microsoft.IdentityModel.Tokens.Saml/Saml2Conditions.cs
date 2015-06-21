using System;

namespace Microsoft.IdentityModel.Tokens.Saml2
{
    public class Saml2Conditions
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
