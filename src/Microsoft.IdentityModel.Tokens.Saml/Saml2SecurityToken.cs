using System;

namespace Microsoft.IdentityModel.Tokens.Saml2
{
    public class Saml2SecurityToken : SecurityToken
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

        public Saml2Conditions Conditions { get; }

        public override SecurityKey SigningKey
        {
            get;
            set;
        }

        public override string Issuer { get; }
    }
}