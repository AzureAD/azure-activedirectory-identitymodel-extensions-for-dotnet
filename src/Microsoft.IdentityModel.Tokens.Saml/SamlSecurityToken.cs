using System;

namespace Microsoft.IdentityModel.Tokens.Saml
{
    public class SamlSecurityToken : SecurityToken
    {
        public override string Id
        {
            get
            {
                throw new NotImplementedException();
            }
        }

        public override SecurityKey SecurityKey
        {
            get
            {
                throw new NotImplementedException();
            }
        }

        public override DateTime ValidFrom
        {
            get
            {
                throw new NotImplementedException();
            }
        }

        public override DateTime ValidTo
        {
            get
            {
                throw new NotImplementedException();
            }
        }

        public override SecurityKey SigningKey
        {
            get;
            set;
        }

        public SamlConditions Conditions { get; set; }

    }
}