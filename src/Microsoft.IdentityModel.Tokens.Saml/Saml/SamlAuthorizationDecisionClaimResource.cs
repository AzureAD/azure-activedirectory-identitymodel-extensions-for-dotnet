//-----------------------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
//-----------------------------------------------------------------------------

using System.Runtime.Serialization;

namespace Microsoft.IdentityModel.Tokens.Saml
{

    [DataContract]
    public class SamlAuthorizationDecisionClaimResource
    {
        // TODO - do we need this class?
        //[DataMember]
        //string resource;

        //[DataMember]
        //SamlAccessDecision accessDecision;

        //[DataMember]
        //string actionNamespace;

        //[DataMember]
        //string actionName;

        //[OnDeserialized]
        //void OnDeserialized(StreamingContext ctx)
        //{
        //    if (string.IsNullOrEmpty(resource))
        //        throw LogHelper.LogArgumentNullException(nameof(resource");

        //    if (string.IsNullOrEmpty(actionName))
        //        throw LogHelper.LogArgumentNullException(nameof(actionName");
        //}

        //public SamlAuthorizationDecisionClaimResource(string resource, SamlAccessDecision accessDecision, string actionNamespace, string actionName)
        //{
        //    if (string.IsNullOrEmpty(resource))
        //        throw LogHelper.LogArgumentNullException(nameof(resource");
        //    if (string.IsNullOrEmpty(actionName))
        //        throw LogHelper.LogArgumentNullException(nameof(actionName");

        //    this.resource = resource;
        //    this.accessDecision = accessDecision;
        //    this.actionNamespace = actionNamespace;
        //    this.actionName = actionName;
        //}

        //public string Resource
        //{
        //    get
        //    {
        //        return this.resource;
        //    }
        //}

        //public SamlAccessDecision AccessDecision
        //{
        //    get
        //    {
        //        return this.accessDecision;
        //    }
        //}

        //public string ActionNamespace
        //{
        //    get
        //    {
        //        return this.actionNamespace;
        //    }
        //}

        //public string ActionName
        //{
        //    get
        //    {
        //        return this.actionName;
        //    }
        //}

        //public override bool Equals(object obj)
        //{
        //    if (obj == null)
        //        return false;

        //    if (ReferenceEquals(this, obj))
        //        return true;

        //    SamlAuthorizationDecisionClaimResource rhs = obj as SamlAuthorizationDecisionClaimResource;
        //    if (rhs == null)
        //        return false;

        //    return ((this.ActionName == rhs.ActionName) && (this.ActionNamespace == rhs.ActionNamespace) &&
        //        (this.Resource == rhs.Resource) && (this.AccessDecision == rhs.AccessDecision));
        //}

        //public override int GetHashCode()
        //{
        //    return (this.resource.GetHashCode() ^ this.accessDecision.GetHashCode());
        //}
    }
}
