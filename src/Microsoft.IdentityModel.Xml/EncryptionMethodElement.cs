//------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
//------------------------------------------------------------

using System.Xml;
using Microsoft.IdentityModel.Logging;

namespace Microsoft.IdentityModel.Xml
{   
    public class EncryptionMethodElement
    {
        public string Algorithm { get; set; }

        public string Parameters { get; set; }

        public void ReadXml( XmlDictionaryReader reader )
        {
            if (reader == null)
                throw LogHelper.LogArgumentNullException(nameof(reader));

            reader.MoveToContent();
            if ( !reader.IsStartElement(XmlEncryptionStrings.EncryptionMethod, XmlEncryptionStrings.Namespace ) )
                return;

            Algorithm = reader.GetAttribute(XmlEncryptionStrings.Algorithm, null );

            if ( !reader.IsEmptyElement )
            {
                //
                // Trace unread missing element
                //

                string xml = reader.ReadOuterXml();
            }
            else
            {
                //
                // Read to the next element
                //
                reader.Read();
            }
        }

        public void WriteXml( XmlWriter writer )
        {
            writer.WriteStartElement(XmlEncryptionStrings.Prefix, XmlEncryptionStrings.EncryptionMethod, XmlEncryptionStrings.Namespace );

            writer.WriteAttributeString(XmlEncryptionStrings.Algorithm, null, Algorithm );

            // <EncryptionMethod>

            writer.WriteEndElement(); 
        }

    }
}
