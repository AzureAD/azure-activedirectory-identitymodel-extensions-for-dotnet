//------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
//------------------------------------------------------------

using System.Security.Cryptography;
using System.Xml;
using Microsoft.IdentityModel.Logging;

namespace Microsoft.IdentityModel.Xml
{
    struct ElementWithAlgorithmAttribute
    {
        readonly string elementName;

        public ElementWithAlgorithmAttribute(string elementName)
        {
            if (string.IsNullOrEmpty(elementName))
                throw LogHelper.LogArgumentNullException(nameof(elementName));

            this.elementName = elementName;
            Algorithm = null;
            Prefix = SignedXml.DefaultPrefix;
        }

        public string Algorithm { get; set; }

        public string Prefix { get; set; }

        public void ReadFrom(XmlDictionaryReader reader)
        {
            reader.MoveToStartElement(this.elementName, XmlSignatureStrings.Namespace);
            Prefix = reader.Prefix;
            bool isEmptyElement = reader.IsEmptyElement;
            Algorithm = reader.GetAttribute(XmlSignatureStrings.Algorithm, null);
            if (Algorithm == null)
                throw LogHelper.LogExceptionMessage(new CryptographicException("RequiredAttributeMissing"));

            reader.Read();
            reader.MoveToContent();

            if (!isEmptyElement)
            {
                reader.MoveToContent();
                reader.ReadEndElement();
            }
        }

        public void WriteTo(XmlDictionaryWriter writer)
        {
            writer.WriteStartElement(Prefix, elementName, XmlSignatureStrings.Namespace);
            writer.WriteStartAttribute(XmlSignatureStrings.Algorithm, null);
            writer.WriteString(Algorithm);
            writer.WriteEndAttribute();
            writer.WriteEndElement();
        }
    }
}