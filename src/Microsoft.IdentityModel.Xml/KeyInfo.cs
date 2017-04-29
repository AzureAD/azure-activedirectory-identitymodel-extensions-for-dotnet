//------------------------------------------------------------------------------
//
// Copyright (c) Microsoft Corporation.
// All rights reserved.
//
// This code is licensed under the MIT License.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files(the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and / or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions :
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
//
//------------------------------------------------------------------------------

using System;
using System.Security.Cryptography.X509Certificates;
using System.Xml;
using Microsoft.IdentityModel.Logging;

namespace Microsoft.IdentityModel.Xml
{
    /// <summary>
    /// Reads and writes a  https://www.w3.org/TR/2001/PR-xmldsig-core-20010820/#sec-KeyInfo
    /// </summary>
    /// <remarks>Only a single 'X509Certificate' is supported. Multiples that include intermediate and root certs are not supported.</remarks>
    public class KeyInfo
    {
        /// <summary>
        /// Instantiates a <see cref="Keyinfo"/>.
        /// </summary>
        public KeyInfo() {}

        /// <summary>
        /// Get the 'X509CertificateData' value
        /// </summary>
        public string CertificateData { get; set; }

        /// <summary>
        /// Gets and sets the IssuerName that is part of a 'X509IssuerSerial'
        /// </summary>
        public string IssuerName { get; set; }

        /// <summary>
        /// Gets and sets the a kid that reflects the type of 'X509Data'
        /// For multiple X509Data the last one will be used
        /// </summary>
        public string Kid { get; set; }

        /// <summary>
        /// Gets and sets the Uri associated with the RetrievalMethod
        /// </summary>
        public string RetrievalMethodUri { get; set; }

        /// <summary>
        /// Get and sets the SerialNumber that is part of a 'X509IssuerSerial'
        /// </summary>
        public string SerialNumber { get; set; }

        /// <summary>
        /// Gets and sets the 'X509SKI' value
        /// </summary>
        public string SKI { get; set; }

        /// <summary>
        /// Get and sets the 'X509SubjectName' value
        /// </summary>
        public string SubjectName { get; set; }

        /// <summary>
        /// Reads https://www.w3.org/TR/2001/PR-xmldsig-core-20010820/#sec-KeyInfo
        /// </summary>
        /// <param name="reader"><see cref="XmlReader"/> pointing at <see cref="XmlSignatureConstants.Elements.KeyInfo"/>.</param>
        /// <remarks>Only handles IssuerSerial, Ski, SubjectName, Certificate. Unsupported types are skipped. Only a X509 data element is supported.</remarks>
        public virtual void ReadFrom(XmlReader reader)
        {
            XmlUtil.CheckReaderOnEntry(reader, XmlSignatureConstants.Elements.KeyInfo, XmlSignatureConstants.Namespace);

            try
            {
                // <KeyInfo>
                reader.ReadStartElement();

                while (reader.IsStartElement())
                {
                    // <X509Data>
                    if (reader.IsStartElement(XmlSignatureConstants.Elements.X509Data, XmlSignatureConstants.Namespace))
                    {
                        reader.ReadStartElement(XmlSignatureConstants.Elements.X509Data, XmlSignatureConstants.Namespace);
                        while (reader.IsStartElement())
                        {
                            if (reader.IsStartElement(XmlSignatureConstants.Elements.X509Certificate, XmlSignatureConstants.Namespace))
                            {
                                // multiple certs
                                if (CertificateData != null)
                                    throw XmlUtil.LogReadException(LogMessages.IDX21015, XmlSignatureConstants.Elements.X509Certificate);

                                ReadCertificate(reader);
                            }
                            else if (reader.IsStartElement(XmlSignatureConstants.Elements.X509IssuerSerial, XmlSignatureConstants.Namespace))
                            {
                                if (SerialNumber != null)
                                    throw XmlUtil.LogReadException(LogMessages.IDX21015, XmlSignatureConstants.Elements.X509IssuerSerial);

                                ReadIssuerSerial(reader);
                            }
                            else if (reader.IsStartElement(XmlSignatureConstants.Elements.X509SKI, XmlSignatureConstants.Namespace))
                            {
                                if (SKI != null)
                                    throw XmlUtil.LogReadException(LogMessages.IDX21015, XmlSignatureConstants.Elements.X509SKI);

                                ReadSKI(reader);
                            }
                            else if (reader.IsStartElement(XmlSignatureConstants.Elements.X509SubjectName, XmlSignatureConstants.Namespace))
                            {
                                if (SubjectName != null)
                                    throw XmlUtil.LogReadException(LogMessages.IDX21015, XmlSignatureConstants.Elements.X509SubjectName);

                                ReadSubjectName(reader);
                            }
                            else
                            {
                                // Skip the element since it is not one of  <X509Certificate>, <X509IssuerSerial>, <X509SKI>, <X509SubjectName>
                                IdentityModelEventSource.Logger.WriteWarning(LogMessages.IDX21300, reader.ReadOuterXml());
                            }
                        }

                        // </X509Data>
                        reader.ReadEndElement();
                    }
                    // <RetrievalMethod>
                    else if (reader.IsStartElement(XmlSignatureConstants.Elements.RetrievalMethod, XmlSignatureConstants.Namespace))
                    {
                        RetrievalMethodUri = reader.GetAttribute(XmlSignatureConstants.Attributes.URI);
                        reader.ReadOuterXml();
                    }
                    // TODO <KeyName>
                    //else if (reader.IsStartElement(XmlSignatureConstants.Elements.KeyName, XmlSignatureConstants.Namespace))
                    //{
                    //}
                    // TODO <KeyValue>
                    //else if (reader.IsStartElement(XmlSignatureConstants.Elements.KeyValue, XmlSignatureConstants.Namespace))
                    //{
                    //}
                    else
                    {
                        // Skip the element since it is not one of  <RetrievalMethod>, <X509Data>
                        IdentityModelEventSource.Logger.WriteWarning(LogMessages.IDX21300, reader.ReadOuterXml());
                    }
                }

                // </KeyInfo>
                reader.ReadEndElement();
            }
            catch(Exception ex)
            {
                if (ex is XmlReadException)
                    throw;

                throw XmlUtil.LogReadException(LogMessages.IDX21017, ex, XmlSignatureConstants.Elements.KeyInfo, ex);
            }
        }

        /// <summary>
        /// Parses the "X509Certificate" element.
        /// </summary>
        /// <param name="reader">The <see cref="XmlReader"/> currently positioning on the <see cref="XmlSignatureConstants.Elements.X509Certificate"/> element.</param>
        private void ReadCertificate(XmlReader reader)
        {
            CertificateData = reader.ReadElementContentAsString();
            var embededCert = new X509Certificate2(Convert.FromBase64String(CertificateData));
            Kid = embededCert.Thumbprint;
        }

        /// <summary>
        /// Parses the "X509IssuerSerial" element.
        /// </summary>
        /// <param name="reader">The <see cref="XmlReader"/> currently positioning on the <see cref="XmlSignatureConstants.Elements.X509IssuerSerial"/> element.</param>
        private void ReadIssuerSerial(XmlReader reader)
        {
            reader.ReadStartElement(XmlSignatureConstants.Elements.X509IssuerSerial, XmlSignatureConstants.Namespace);

            if (!reader.IsStartElement(XmlSignatureConstants.Elements.X509IssuerName, XmlSignatureConstants.Namespace))
                throw XmlUtil.LogReadException(LogMessages.IDX21011, XmlSignatureConstants.Elements.X509IssuerName, reader.LocalName);

            IssuerName = reader.ReadElementContentAsString(XmlSignatureConstants.Elements.X509IssuerName, XmlSignatureConstants.Namespace);

            if (!reader.IsStartElement(XmlSignatureConstants.Elements.X509SerialNumber, XmlSignatureConstants.Namespace))
                throw XmlUtil.LogReadException(LogMessages.IDX21011, XmlSignatureConstants.Elements.X509SerialNumber, reader.LocalName);

            SerialNumber = reader.ReadElementContentAsString(XmlSignatureConstants.Elements.X509SerialNumber, XmlSignatureConstants.Namespace);
            Kid = SerialNumber;

            reader.ReadEndElement();
         }

        /// <summary>
        /// Parses the "X509SKI" element.
        /// </summary>
        /// <param name="reader">The <see cref="XmlReader"/> currently pointing at the <see cref="XmlSignatureConstants.Elements.X509SKI"/> element.</param>
        private void ReadSKI(XmlReader reader)
        {
            SKI = reader.ReadElementContentAsString();
            Kid = SKI;
        }

        /// <summary>
        /// Parses the "X509SubjectName" element.
        /// </summary>
        /// <param name="reader">The <see cref="XmlReader"/> currently pointing at the <see cref="XmlSignatureConstants.Elements.X509SubjectName"/> element.</param>
        private void ReadSubjectName(XmlReader reader)
        {
            SubjectName = reader.ReadElementContentAsString();
            Kid = SubjectName;
        }

        public virtual void WriteTo(XmlWriter writer)
        {
            if (writer == null)
                LogHelper.LogArgumentNullException(nameof(writer));

            // TODO serialize
        }
    }
}
