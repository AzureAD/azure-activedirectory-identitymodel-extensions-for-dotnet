using System.ServiceModel.Channels;

namespace System.ServiceModel.Federation
{
    internal class WsFederationBindingElement : BindingElement
    {
        public WsFederationBindingElement(IssuedTokenParameters issuedTokenParameters, SecurityBindingElement securityBindingElement)
        {
            IssuedTokenParameters = issuedTokenParameters;
            SecurityBindingElement = securityBindingElement;
        }

        public IssuedTokenParameters IssuedTokenParameters { get; }

        public SecurityBindingElement SecurityBindingElement { get; }

        public override BindingElement Clone()
        {
            return new WsFederationBindingElement(IssuedTokenParameters, SecurityBindingElement);
        }

        public override T GetProperty<T>(BindingContext context)
        {
            return SecurityBindingElement.GetProperty<T>(context);
        }
    }
}
