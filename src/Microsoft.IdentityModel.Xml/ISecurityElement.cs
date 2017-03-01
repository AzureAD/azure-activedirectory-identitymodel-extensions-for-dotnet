//------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
//------------------------------------------------------------

namespace Microsoft.IdentityModel.Xml
{
    using System.Xml;

    public interface ISecurityElement
    {
        bool HasId { get; }

        string Id { get; }

        void WriteTo(XmlDictionaryWriter writer);
    }
}
