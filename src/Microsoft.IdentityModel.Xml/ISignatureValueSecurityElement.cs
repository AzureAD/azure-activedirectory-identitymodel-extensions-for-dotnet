//------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
//------------------------------------------------------------

namespace Microsoft.IdentityModel.Xml
{
    using System.Xml;

    public interface ISignatureValueSecurityElement : ISecurityElement
    {
        byte[] GetSignatureValue();
    }
}
