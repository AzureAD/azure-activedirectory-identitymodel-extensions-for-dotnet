//------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
//------------------------------------------------------------

using System;
using System.Xml;
using Microsoft.IdentityModel.Logging;

namespace Microsoft.IdentityModel.Xml
{
    public class CipherDataElement
    {
        byte[] _iv;
        byte[] _cipherText;

        public byte[] CipherValue
        {
            get
            {
                if ( _iv != null )
                {
                    byte[] buffer = new byte[_iv.Length + _cipherText.Length];
                    Buffer.BlockCopy( _iv, 0, buffer, 0, _iv.Length );
                    Buffer.BlockCopy( _cipherText, 0, buffer, _iv.Length, _cipherText.Length );
                    _iv = null;
                }

                return _cipherText;
            }
            set
            {
                _cipherText = value;
            }
        }

        public void ReadXml( XmlDictionaryReader reader )
        {
            if (reader == null)
                LogHelper.LogArgumentNullException(nameof(reader));

            reader.MoveToContent();
            if (!reader.IsStartElement(XmlEncryptionStrings.CipherData, XmlEncryptionStrings.Namespace))
                throw LogHelper.LogExceptionMessage(new XmlEncryptionException($"Expection start element {XmlEncryptionStrings.CipherData}"));

            reader.ReadStartElement(XmlEncryptionStrings.CipherData, XmlEncryptionStrings.Namespace );
            reader.ReadStartElement(XmlEncryptionStrings.CipherValue, XmlEncryptionStrings.Namespace );

            _cipherText = reader.ReadContentAsBase64();
            _iv         = null;

            // <CipherValue>
            reader.MoveToContent();           
            reader.ReadEndElement();

            
            // <CipherData>
            reader.MoveToContent();
            reader.ReadEndElement(); 
        }

        public void SetCipherValueFragments( byte[] iv, byte[] cipherText )
        {
            _iv         = iv;
            _cipherText = cipherText;
        }

        public void WriteXml( XmlWriter writer )
        {
            writer.WriteStartElement(XmlEncryptionStrings.Prefix, XmlEncryptionStrings.CipherData, XmlEncryptionStrings.Namespace );
            writer.WriteStartElement(XmlEncryptionStrings.Prefix, XmlEncryptionStrings.CipherValue, XmlEncryptionStrings.Namespace );

            if ( _iv != null )
                writer.WriteBase64( _iv, 0, _iv.Length );

            writer.WriteBase64( _cipherText, 0, _cipherText.Length );

            writer.WriteEndElement(); // CipherValue
            writer.WriteEndElement(); // CipherData
        }
    }
}
