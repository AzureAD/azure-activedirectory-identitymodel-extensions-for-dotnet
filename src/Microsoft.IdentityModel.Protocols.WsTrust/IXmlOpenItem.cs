// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System.Collections.Generic;
using System.Xml;

namespace Microsoft.IdentityModel.Protocols.WsTrust
{
    /// <summary>
    /// Defines an interface for handling additional elements and attributes
    /// </summary>
    public interface IXmlOpenItem
    {
        /// <summary>
        /// 
        /// </summary>
        IList<XmlElement> AdditionalXmlElements { get; }

        /// <summary>
        /// 
        /// </summary>
        IList<XmlAttribute> AdditionalXmlAttributes { get; }
    }
}
