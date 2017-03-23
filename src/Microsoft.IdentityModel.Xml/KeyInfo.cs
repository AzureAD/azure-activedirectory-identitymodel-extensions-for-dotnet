//------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
//------------------------------------------------------------

using System.Xml;
using Microsoft.IdentityModel.Logging;

namespace Microsoft.IdentityModel.Xml
{
    public class KeyInfo
    {
        private string _issuerName;
        private string _serialNumber;
        private string _retrieval;
        private string _x509CertificateData;
        private string _ski;

        public KeyInfo() {}

        public string RetrievalMethod
        {
            get { return _retrieval; }
        }

        public string X509CertificateData
        {
            get { return _x509CertificateData; }
        }

        public virtual void ReadFrom(XmlReader reader)
        {
            if (reader == null)
                throw LogHelper.LogArgumentNullException(nameof(reader));

            reader.MoveToContent();
            if (reader.IsStartElement(XmlSignatureConstants.Elements.KeyInfo, XmlSignatureConstants.Namespace))
            {
                // <KeyInfo>
                reader.ReadStartElement();
                while (reader.IsStartElement())
                {
                    // <RetrievalMethod>
                    if (reader.IsStartElement(XmlSignatureConstants.Elements.RetrievalMethod, XmlSignatureConstants.Namespace))
                    {
                        string method = reader.GetAttribute(XmlSignatureConstants.Attributes.URI);
                        if (!string.IsNullOrEmpty(method))
                        {
                            _retrieval = method;
                        }
                    }

                    if (reader.IsStartElement(XmlSignatureConstants.Elements.X509Data, XmlSignatureConstants.Namespace))
                    {
                        reader.ReadStartElement(XmlSignatureConstants.Elements.X509Data, XmlSignatureConstants.Namespace);
                        while (reader.IsStartElement())
                        {
                            if (reader.IsStartElement(XmlSignatureConstants.Elements.X509IssuerSerial, XmlSignatureConstants.Namespace))
                                ReadIssuerSerial(reader);
                            else if (reader.IsStartElement(XmlSignatureConstants.Elements.X509SKI, XmlSignatureConstants.Namespace))
                                ReadSujectKeyIdentifier(reader);
                            else if (reader.IsStartElement(XmlSignatureConstants.Elements.X509Certificate, XmlSignatureConstants.Namespace))
                                ReadCertificate(reader);
                            else
                            {
                                // Skip the element since it is not one of <X509IssuerSerial>, <X509SKI> and <X509Certificate>
                                reader.Skip();
                            }
                        }
                        reader.ReadEndElement(); // X509Data
                    }
                }
                reader.ReadEndElement(); // KeyInfo
            }
        }

        /// <summary>
        /// Parses the "X509Certificate" element.
        /// </summary>
        /// <param name="reader">The <see cref="XmlReader"/> currently positioning on the "X509IssuerSerial" element. </param>
        private void ReadCertificate(XmlReader reader)
        {
            reader.ReadStartElement(XmlSignatureConstants.Elements.X509Certificate, XmlSignatureConstants.Namespace);
            _x509CertificateData = reader.ReadContentAsString();
            reader.ReadEndElement();
        }

        /// <summary>
        /// Parses the "X509SubjectKeyIdentifier" element.
        /// </summary>
        /// <param name="reader">The <see cref="XmlReader"/> currently positioning on the "X509SerialNumber" element. </param>
        private void ReadSujectKeyIdentifier(XmlReader reader)
        {
            reader.ReadStartElement(XmlSignatureConstants.Elements.X509SerialNumber, XmlSignatureConstants.Namespace);
            _ski = reader.ReadElementContentAsString();
            reader.ReadEndElement();
        }

        /// <summary>
        /// Parses the "X509IssuerSerial" element.
        /// </summary>
        /// <param name="reader">The <see cref="XmlReader"/> currently positioning on the "X509IssuerSerial" element. </param>
        private void ReadIssuerSerial(XmlReader reader)
        {
            reader.ReadStartElement(XmlSignatureConstants.Elements.X509IssuerSerial, XmlSignatureConstants.Namespace);

            if (!reader.IsStartElement(XmlSignatureConstants.Elements.X509IssuerName, XmlSignatureConstants.Namespace))
                throw new XmlSignedInfoException($"Expecting: {XmlSignatureConstants.Elements.X509IssuerName}, found {reader.LocalName}.");

            _issuerName = reader.ReadElementContentAsString(XmlSignatureConstants.Elements.X509IssuerName, XmlSignatureConstants.Namespace);

            if (!reader.IsStartElement(XmlSignatureConstants.Elements.X509SerialNumber, XmlSignatureConstants.Namespace))
                throw new XmlSignedInfoException($"Expecting: {XmlSignatureConstants.Elements.X509SerialNumber}, found {reader.LocalName}.");

            _serialNumber = reader.ReadElementContentAsString(XmlSignatureConstants.Elements.X509SerialNumber, XmlSignatureConstants.Namespace);

            reader.ReadEndElement();
         }
    }
}
