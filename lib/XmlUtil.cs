//------------------------------------------------------------------------------
//     Copyright (c) Microsoft Corporation.  All rights reserved.
//------------------------------------------------------------------------------

namespace System.IdentityModel
{
    using System.Collections.Generic;
    using System.Xml;

    internal static class XmlUtil
    {
        /// <summary>
        /// List containing only those XmlNodes that were XmlElements.
        /// </summary>
        /// <param name="nodeList">nodes to parse</param>
        /// <returns>List containing only those XmlNodes that were XmlElements</returns>
        /// <remarks>A null list will return an empty List</remarks>
        public static List<XmlElement> GetXmlElements(XmlNodeList nodeList)
        {
            List<XmlElement> xmlElements = new List<XmlElement>();

            if ( null != nodeList )
            {
                foreach ( XmlNode node in nodeList )
                {
                    XmlElement tempElement = node as XmlElement;
                    if ( tempElement != null )
                    {
                        xmlElements.Add( tempElement );
                    }
                }
            }

            return xmlElements;
        }
    }
}