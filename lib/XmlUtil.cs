//-----------------------------------------------------------------------
// Copyright (c) Microsoft Open Technologies, Inc.
// All Rights Reserved
// Apache License 2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// 
// http://www.apache.org/licenses/LICENSE-2.0
// 
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//-----------------------------------------------------------------------

namespace System.IdentityModel
{
    using System.Collections.Generic;
    using System.Xml;

    /// <summary>
    /// Simple Xml utility class.
    /// </summary>
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

            if (null != nodeList)
            {
                foreach (XmlNode node in nodeList)
                {
                    XmlElement tempElement = node as XmlElement;
                    if (tempElement != null)
                    {
                        xmlElements.Add(tempElement);
                    }
                }
            }

            return xmlElements;
        }
    }
}