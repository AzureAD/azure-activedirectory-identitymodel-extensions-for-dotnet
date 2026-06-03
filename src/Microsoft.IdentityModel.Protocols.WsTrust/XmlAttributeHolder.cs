// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Xml;

namespace Microsoft.IdentityModel.Xml
{
    internal struct XmlAttributeHolder
    {
        public static XmlAttributeHolder[] EmptyArray = Array.Empty<XmlAttributeHolder>();

        public XmlAttributeHolder(string prefix, string localName, string ns, string value)
        {
            Prefix = prefix;
            LocalName = localName;
            NamespaceUri = ns;
            Value = value;
        }

        public string Prefix { get; }

        public string NamespaceUri { get; }

        public string LocalName { get; }

        public string Value { get; }

        public static XmlAttributeHolder[] ReadAttributes(XmlDictionaryReader reader)
        {
            if (reader.AttributeCount == 0)
                return EmptyArray;

            XmlAttributeHolder[] attributes = new XmlAttributeHolder[reader.AttributeCount];
            reader.MoveToFirstAttribute();
            for (int i = 0; i < attributes.Length; i++)
            {
                string ns = reader.NamespaceURI;
                string localName = reader.LocalName;
                string prefix = reader.Prefix;
                string value = string.Empty;
                while (reader.ReadAttributeValue())
                {
                    if (value.Length == 0)
                        value = reader.Value;
                    else
                        value += reader.Value;
                }

                attributes[i] = new XmlAttributeHolder(prefix, localName, ns, value);
                reader.MoveToNextAttribute();
            }

            reader.MoveToElement();
            return attributes;
        }

        public static string GetAttribute(XmlAttributeHolder[] attributes, string localName, string ns)
        {
            for (int i = 0; i < attributes.Length; i++)
            {
                // if a prefix exist, then the namespace comes into play
                if (!string.IsNullOrEmpty(attributes[i].Prefix))
                {
                    if (attributes[i].LocalName == localName && attributes[i].NamespaceUri == ns)
                        return attributes[i].Value;
                }
                else
                {
                    if (attributes[i].LocalName == localName)
                        return attributes[i].Value;
                }
            }

            return null;
        }
    }
}
