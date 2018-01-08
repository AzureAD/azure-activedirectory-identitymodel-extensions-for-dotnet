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
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Xml;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Tokens;
using static Microsoft.IdentityModel.Logging.LogHelper;

namespace Microsoft.IdentityModel.Xml
{
    /// <summary>
    /// Reads and writes XML associated with XML DSig https://www.w3.org/TR/2001/PR-xmldsig-core-20010820
    /// </summary>
    public class DSigSerializer
    {
        private static DSigSerializer _default;
        private string _preferredPrefix = XmlSignatureConstants.PreferredPrefix;

        /// <summary>
        /// Returns the default <see cref="DSigSerializer"/> instance.
        /// </summary>
        public static DSigSerializer Default
        {
            get
            {
                return _default;
            }
            set
            {
                _default = value ?? throw LogArgumentNullException(nameof(value));
            }
        }

        /// <summary>
        /// Static constructor that initializes the default <see cref="CryptoProviderFactory"/>.
        /// </summary>
        static DSigSerializer()
        {
            Default = new DSigSerializer();
        }

        /// <summary>
        /// Initializes an instance of <see cref="DSigSerializer"/>
        /// </summary>
        public DSigSerializer()
        {
        }

        /// <summary>
        /// Gets or sets the prefix to use when writing xml.
        /// </summary>
        public string PreferredPrefix
        {
            get => _preferredPrefix;
            set
            {
                if (string.IsNullOrEmpty(value))
                    throw LogExceptionMessage(new ArgumentNullException(nameof(value)));

                _preferredPrefix = value;
            }
        }

        /// <summary>
        /// Reads XML conforming to https://www.w3.org/TR/2001/PR-xmldsig-core-20010820/#sec-KeyInfo
        /// </summary>
        /// <param name="reader"><see cref="XmlReader"/> pointing positioned on a &lt;KeyInfo> element.</param>
        /// <exception cref="ArgumentNullException">if <paramref name="reader"/> is null.</exception>
        /// <exception cref="XmlReadException">if there is a problem reading the XML.</exception>
        /// <remarks>Only handles IssuerSerial, Ski, SubjectName, Certificate. Unsupported types are skipped. Only a X509 data element is supported.</remarks>
        public virtual KeyInfo ReadKeyInfo(XmlReader reader)
        {
            XmlUtil.CheckReaderOnEntry(reader, XmlSignatureConstants.Elements.KeyInfo, XmlSignatureConstants.Namespace);

            var keyInfo = new KeyInfo();
            try
            {
                bool isEmptyElement = reader.IsEmptyElement;

                // <KeyInfo>
                reader.ReadStartElement();

                while (reader.IsStartElement())
                {
                    // <X509Data>
                    if (reader.IsStartElement(XmlSignatureConstants.Elements.X509Data, XmlSignatureConstants.Namespace))
                    {
                        keyInfo.X509Data.Add(ReadX509Data(reader));
                    }
                    // <RetrievalMethod>
                    else if (reader.IsStartElement(XmlSignatureConstants.Elements.RetrievalMethod, XmlSignatureConstants.Namespace))
                    {
                        keyInfo.RetrievalMethodUri = reader.GetAttribute(XmlSignatureConstants.Attributes.URI);
                        reader.ReadOuterXml();
                    }
                    // <KeyName>
                    else if (reader.IsStartElement(XmlSignatureConstants.Elements.KeyName, XmlSignatureConstants.Namespace))
                    {
                        keyInfo.KeyName = reader.ReadElementContentAsString(XmlSignatureConstants.Elements.KeyName, XmlSignatureConstants.Namespace);
                    }
                    // <KeyValue>
                    else if (reader.IsStartElement(XmlSignatureConstants.Elements.KeyValue, XmlSignatureConstants.Namespace))
                    {
                        reader.ReadStartElement(XmlSignatureConstants.Elements.KeyValue, XmlSignatureConstants.Namespace);
                            if (reader.IsStartElement(XmlSignatureConstants.Elements.RSAKeyValue, XmlSignatureConstants.Namespace))
                            {
                                // Multiple RSAKeyValues were found
                                if (keyInfo.RSAKeyValue != null)
                                    throw XmlUtil.LogReadException(LogMessages.IDX30015, XmlSignatureConstants.Elements.RSAKeyValue);

                                keyInfo.RSAKeyValue = ReadRSAKeyValue(reader);
                            }
                            else
                            {
                                // Skip the element since it is not an <RSAKeyValue>
                                LogHelper.LogWarning(LogMessages.IDX30300, reader.ReadOuterXml());
                            }

                        // </KeyValue>
                        reader.ReadEndElement();
                    }
                    else
                    {
                        // Skip the element since it is not one of  <RetrievalMethod>, <X509Data>, <KeyValue>
                        LogHelper.LogWarning(LogMessages.IDX30300, reader.ReadOuterXml());
                    }
                }

                // </KeyInfo>
                if (!isEmptyElement)
                    reader.ReadEndElement();

            }
            catch(Exception ex)
            {
                if (ex is XmlReadException)
                    throw;

                throw XmlUtil.LogReadException(LogMessages.IDX30017, ex, XmlSignatureConstants.Elements.KeyInfo, ex);
            }

            return keyInfo;
        }

        /// <summary>
        /// Reads the "X509DataElement" element conforming to https://www.w3.org/TR/2001/PR-xmldsig-core-20010820/#sec-X509Data.
        /// </summary>
        /// <param name="reader">A <see cref="XmlReader"/> positioned on a <see cref="XmlSignatureConstants.Elements.X509Data"/> element.</param>
        private X509Data ReadX509Data(XmlReader reader)
        {
            var data = new X509Data();

            if (reader.IsEmptyElement)
                throw XmlUtil.LogReadException(LogMessages.IDX30108);

            reader.ReadStartElement(XmlSignatureConstants.Elements.X509Data, XmlSignatureConstants.Namespace);
            while (reader.IsStartElement())
            {
                if (reader.IsStartElement(XmlSignatureConstants.Elements.X509Certificate, XmlSignatureConstants.Namespace))
                {
                    data.Certificates.Add(reader.ReadElementContentAsString());
                }
                else if (reader.IsStartElement(XmlSignatureConstants.Elements.X509IssuerSerial, XmlSignatureConstants.Namespace))
                {
                    if (data.IssuerSerial != null)
                        throw XmlUtil.LogReadException(LogMessages.IDX30015, XmlSignatureConstants.Elements.X509IssuerSerial);
                    data.IssuerSerial = ReadIssuerSerial(reader);
                }
                else if (reader.IsStartElement(XmlSignatureConstants.Elements.X509SKI, XmlSignatureConstants.Namespace))
                {
                    if (data.SKI != null)
                        throw XmlUtil.LogReadException(LogMessages.IDX30015, XmlSignatureConstants.Elements.X509SKI);
                    data.SKI = reader.ReadElementContentAsString();
                }
                else if (reader.IsStartElement(XmlSignatureConstants.Elements.X509SubjectName, XmlSignatureConstants.Namespace))
                {
                    if (data.SubjectName != null)
                        throw XmlUtil.LogReadException(LogMessages.IDX30015, XmlSignatureConstants.Elements.X509SubjectName);
                    data.SubjectName = reader.ReadElementContentAsString();
                }
                else if (reader.IsStartElement(XmlSignatureConstants.Elements.X509CRL, XmlSignatureConstants.Namespace))
                {
                    if (data.CRL != null)
                        throw XmlUtil.LogReadException(LogMessages.IDX30015, XmlSignatureConstants.Elements.X509CRL);
                    data.CRL = reader.ReadElementContentAsString();
                }
                else
                {
                    // Skip the element since it is not one of  <X509Certificate>, <X509IssuerSerial>, <X509SKI>, <X509SubjectName>, <X509CRL>
                    LogHelper.LogWarning(LogMessages.IDX30300, reader.ReadOuterXml());
                }
            }

            // </X509Data>
            reader.ReadEndElement();

            return data;
        }

        /// <summary>
        /// Reads the "X509IssuerSerial" element conforming to https://www.w3.org/TR/2001/PR-xmldsig-core-20010820/#sec-X509Data.
        /// </summary>
        /// <param name="reader">A <see cref="XmlReader"/> positioned on a <see cref="XmlSignatureConstants.Elements.X509IssuerSerial"/> element.</param>
        private IssuerSerial ReadIssuerSerial(XmlReader reader)
        {
            reader.ReadStartElement(XmlSignatureConstants.Elements.X509IssuerSerial, XmlSignatureConstants.Namespace);

            if (!reader.IsStartElement(XmlSignatureConstants.Elements.X509IssuerName, XmlSignatureConstants.Namespace))
                throw XmlUtil.LogReadException(LogMessages.IDX30011, XmlSignatureConstants.Namespace, XmlSignatureConstants.Elements.X509IssuerName, reader.NamespaceURI, reader.LocalName);

            var issuerName = reader.ReadElementContentAsString(XmlSignatureConstants.Elements.X509IssuerName, XmlSignatureConstants.Namespace);

            if (!reader.IsStartElement(XmlSignatureConstants.Elements.X509SerialNumber, XmlSignatureConstants.Namespace))
                throw XmlUtil.LogReadException(LogMessages.IDX30011, XmlSignatureConstants.Namespace, XmlSignatureConstants.Elements.X509SerialNumber, reader.NamespaceURI, reader.LocalName);

            var serialNumber = reader.ReadElementContentAsString(XmlSignatureConstants.Elements.X509SerialNumber, XmlSignatureConstants.Namespace);

            reader.ReadEndElement();

            return new IssuerSerial(issuerName, serialNumber);
         }

        /// <summary>
        /// Reads the "RSAKeyValue" element conforming to https://www.w3.org/TR/2001/PR-xmldsig-core-20010820/#sec-RSAKeyValue.
        /// </summary>
        /// <param name="reader">A <see cref="XmlReader"/> positioned on a <see cref="XmlSignatureConstants.Elements.RSAKeyValue"/> element.</param>
        private RSAKeyValue ReadRSAKeyValue(XmlReader reader)
        {
            reader.ReadStartElement(XmlSignatureConstants.Elements.RSAKeyValue, XmlSignatureConstants.Namespace);

            if (!reader.IsStartElement(XmlSignatureConstants.Elements.Modulus, XmlSignatureConstants.Namespace))
                throw XmlUtil.LogReadException(LogMessages.IDX30011, XmlSignatureConstants.Namespace, XmlSignatureConstants.Elements.Modulus, reader.NamespaceURI, reader.LocalName);

            string modulus = reader.ReadElementContentAsString(XmlSignatureConstants.Elements.Modulus, XmlSignatureConstants.Namespace);

            if (!reader.IsStartElement(XmlSignatureConstants.Elements.Exponent, XmlSignatureConstants.Namespace))
                throw XmlUtil.LogReadException(LogMessages.IDX30011, XmlSignatureConstants.Namespace, XmlSignatureConstants.Elements.Exponent, reader.NamespaceURI, reader.LocalName);

            string exponent = reader.ReadElementContentAsString(XmlSignatureConstants.Elements.Exponent, XmlSignatureConstants.Namespace);

            reader.ReadEndElement();

            return new RSAKeyValue(modulus, exponent);    
        }

        /// <summary>
        /// Reads XML conforming to https://www.w3.org/TR/2001/PR-xmldsig-core-20010820/#sec-Signature
        /// </summary>
        /// <param name="reader">a <see cref="XmlReader"/>positioned on a &lt;Signature> element.</param>
        /// <exception cref="ArgumentNullException">if <paramref name="reader"/> is null.</exception>
        /// <exception cref="XmlReadException">if there is a problem reading the XML.</exception>
        /// <returns><see cref="Signature"/></returns>
        public virtual Signature ReadSignature(XmlReader reader)
        {
            try
            {
                // <Signature>
                XmlUtil.CheckReaderOnEntry(reader, XmlSignatureConstants.Elements.Signature, XmlSignatureConstants.Namespace);

                var prefix = reader.Prefix;
                var id = reader.GetAttribute(XmlSignatureConstants.Attributes.Id, null);
                reader.Read();

                var signedInfo = ReadSignedInfo(reader);
                reader.MoveToContent();
                var signatureValue = reader.ReadElementContentAsString().Trim();
                KeyInfo keyInfo = null;
                if (reader.IsStartElement(XmlSignatureConstants.Elements.KeyInfo, XmlSignatureConstants.Namespace))
                    keyInfo = ReadKeyInfo(reader);

                // </Signature>
                reader.MoveToContent();

                // throw if we are not on EndElement, something unexpected
                if (reader.NodeType != XmlNodeType.EndElement)
                    throw XmlUtil.LogReadException(LogMessages.IDX30025, XmlSignatureConstants.Elements.Signature, reader.NodeType, reader.LocalName);

                reader.ReadEndElement();
                return new Signature
                {
                    Id = id,
                    KeyInfo = keyInfo,
                    SignedInfo = signedInfo,
                    SignatureValue = signatureValue
                };
            }
            catch(Exception ex)
            {
                if (ex is XmlReadException)
                    throw;

                throw XmlUtil.LogReadException(LogMessages.IDX30016, ex, XmlSignatureConstants.Elements.Signature);
            }
        }

        /// <summary>
        /// Reads XML conforming to https://www.w3.org/TR/2001/PR-xmldsig-core-20010820/#sec-SignedInfo
        /// </summary>
        /// <param name="reader">a <see cref="XmlReader"/>positioned on a &lt;SignedInfo> element.</param>
        /// <exception cref="ArgumentNullException">if <paramref name="reader"/> is null.</exception>
        /// <exception cref="XmlReadException">if there is a problem reading the XML.</exception>
        /// <returns><see cref="SignedInfo"/></returns>
        public virtual SignedInfo ReadSignedInfo(XmlReader reader)
        {
            XmlUtil.CheckReaderOnEntry(reader, XmlSignatureConstants.Elements.SignedInfo, XmlSignatureConstants.Namespace);

            try
            {
                var defaultNamespace = reader.LookupNamespace(string.Empty);
                var bufferedStream = new MemoryStream();
                var settings = new XmlWriterSettings
                {
                    Encoding = Encoding.UTF8,
                    NewLineHandling = NewLineHandling.None
                };

                // need to read into buffer since the canonicalization reader needs a stream.
                using (XmlWriter bufferWriter = XmlDictionaryWriter.Create(bufferedStream, settings))
                {
                    bufferWriter.WriteNode(reader, true);
                    bufferWriter.Flush();
                }

                bufferedStream.Position = 0;

                //
                // We are creating a XmlDictionaryReader with a hard-coded Max XmlDictionaryReaderQuotas. This is a reader that we
                // are creating over an already buffered content. The content was initially read off user provided XmlDictionaryReader
                // with the correct quotas and hence we know the data is valid.
                //
                using (var canonicalizingReader = XmlDictionaryReader.CreateTextReader(bufferedStream, XmlDictionaryReaderQuotas.Max))
                {
                    var canonicalStream = new MemoryStream();
                    canonicalizingReader.StartCanonicalization(canonicalStream, false, null);
                    canonicalizingReader.MoveToStartElement(XmlSignatureConstants.Elements.SignedInfo, XmlSignatureConstants.Namespace);
                    var prefix = canonicalizingReader.Prefix;
                    var id = canonicalizingReader.GetAttribute(XmlSignatureConstants.Attributes.Id, null);
                    // read <SignedInfo ...> start element
                    canonicalizingReader.Read();
                    var canonicalizationMethod = ReadCanonicalizationMethod(canonicalizingReader);
                    var signatureMethod = ReadSignatureMethod(canonicalizingReader);
                    var reference = ReadReference(canonicalizingReader);

                    if (canonicalizingReader.IsStartElement(XmlSignatureConstants.Elements.Reference, XmlSignatureConstants.Namespace))
                        throw XmlUtil.LogReadException(LogMessages.IDX30020);

                    canonicalizingReader.ReadEndElement();
                    canonicalizingReader.EndCanonicalization();
                    canonicalStream.Flush();

                    return new SignedInfo(reference)
                    {
                        CanonicalizationMethod = canonicalizationMethod,
                        CanonicalStream = canonicalStream,
                        Id = id,
                        SignatureMethod = signatureMethod
                    };
                }
            }
            catch(Exception ex)
            {
                if (ex is XmlReadException)
                    throw;

                throw XmlUtil.LogReadException(LogMessages.IDX30016, ex, XmlSignatureConstants.Elements.SignedInfo);
            }
        }

        /// <summary>
        /// Reads XML conforming to https://www.w3.org/TR/2001/PR-xmldsig-core-20010820/#sec-Reference
        /// </summary>
        /// <param name="reader">a <see cref="XmlReader"/>positioned on a &lt;Reference> element.</param>
        /// <exception cref="ArgumentNullException">if <paramref name="reader"/> is null.</exception>
        /// <exception cref="XmlReadException">if there is a problem reading the XML.</exception>
        /// <returns><see cref="Reference"/></returns>
        public virtual Reference ReadReference(XmlReader reader)
        {
            XmlUtil.CheckReaderOnEntry(reader, XmlSignatureConstants.Elements.Reference, XmlSignatureConstants.Namespace);

            try
            {
                var prefix = reader.Prefix;
                var id = reader.GetAttribute(XmlSignatureConstants.Attributes.Id, null);
                var uri = reader.GetAttribute(XmlSignatureConstants.Attributes.URI, null);
                var type = reader.GetAttribute(XmlSignatureConstants.Attributes.Type, null);

                reader.Read();

                var transforms = ReadTransforms(reader);

                // <DigestMethod> - required
                XmlUtil.CheckReaderOnEntry(reader, XmlSignatureConstants.Elements.DigestMethod, XmlSignatureConstants.Namespace);
                bool isEmptyElement = reader.IsEmptyElement;
                var digestMethod = reader.GetAttribute(XmlSignatureConstants.Attributes.Algorithm, null);
                if (string.IsNullOrEmpty(digestMethod))
                    throw XmlUtil.OnRequiredAttributeMissing(XmlSignatureConstants.Elements.DigestMethod, XmlSignatureConstants.Attributes.Algorithm);

                reader.Read();
                reader.MoveToContent();
                if (!isEmptyElement)
                    reader.ReadEndElement();

                // <DigestValue>
                XmlUtil.CheckReaderOnEntry(reader, XmlSignatureConstants.Elements.DigestValue, XmlSignatureConstants.Namespace);
                var digestValue = reader.ReadElementContentAsString().Trim();
                if (string.IsNullOrEmpty(digestValue))
                    throw XmlUtil.LogReadException(LogMessages.IDX30206, id);

                // </Reference>
                reader.MoveToContent();
                reader.ReadEndElement();

                return new Reference(transforms)
                {
                    DigestMethod = digestMethod,
                    DigestValue = digestValue,
                    Id = id,
                    Prefix = prefix,
                    Type = type,
                    Uri = uri
                };
            }
            catch(Exception ex)
            {
                if (ex is XmlReadException)
                    throw;

                throw XmlUtil.LogReadException(LogMessages.IDX30016, ex, XmlSignatureConstants.Elements.Reference);
            }
        }

        /// <summary>
        /// Reads XML conforming to https://www.w3.org/TR/2001/PR-xmldsig-core-20010820/#sec-Transforms
        /// </summary>
        /// <param name="reader">a <see cref="XmlReader"/>positioned on a &lt;Transforms> element.</param>
        /// <exception cref="ArgumentNullException">if <paramref name="reader"/> is null.</exception>
        /// <exception cref="XmlReadException">if there is a problem reading the XML.</exception>
        /// <returns>a <see cref="IList{T}"/> with the transform names.</returns>
        public IList<string> ReadTransforms(XmlReader reader)
        {
            if (reader == null)
                throw LogArgumentNullException(nameof(reader));

            try
            {
                var transforms = new List<string>();

                // <Transforms> - optional
                if (!reader.IsStartElement(XmlSignatureConstants.Elements.Transforms, XmlSignatureConstants.Namespace))
                    return transforms;

                if (reader.IsEmptyElement)
                {
                    reader.Read();
                    return transforms;
                }

                reader.Read();
                XmlUtil.CheckReaderOnEntry(reader, XmlSignatureConstants.Elements.Transform, XmlSignatureConstants.Namespace);
                while (reader.IsStartElement(XmlSignatureConstants.Elements.Transform, XmlSignatureConstants.Namespace))
                {
                    transforms.Add(ReadTransform(reader));
                }

                // </ Transforms>
                reader.MoveToContent();
                reader.ReadEndElement();

                return transforms;
            }
            catch(Exception ex)
            {
                if (ex is XmlReadException)
                    throw;

                throw XmlUtil.LogReadException(LogMessages.IDX30016, ex, XmlSignatureConstants.Elements.Transforms);
            }
        }

        /// <summary>
        /// Reads XML conforming to https://www.w3.org/TR/2001/PR-xmldsig-core-20010820/#sec-Transforms
        /// </summary>
        /// <param name="reader">a <see cref="XmlReader"/>positioned on a &lt;Transforms> element.</param>
        /// <exception cref="ArgumentNullException">if <paramref name="reader"/> is null.</exception>
        /// <exception cref="XmlReadException">if there is a problem reading the XML.</exception>
        /// <returns>A string with the type of transform.</returns>
        public virtual string ReadTransform(XmlReader reader)
        {
            XmlUtil.CheckReaderOnEntry(reader, XmlSignatureConstants.Elements.Transform);

            try
            {
                var isEmptyElement = reader.IsEmptyElement;
                var algorithm = reader.GetAttribute(XmlSignatureConstants.Attributes.Algorithm, null);
                if (string.IsNullOrEmpty(algorithm))
                    throw XmlUtil.LogReadException(LogMessages.IDX30105);

                reader.Read();
                reader.MoveToContent();
                if (!isEmptyElement)
                {
                    if (reader.IsStartElement(XmlSignatureConstants.ExclusiveC14nInclusiveNamespaces))
                        throw XmlUtil.LogReadException(LogMessages.IDX30107);

                    reader.MoveToContent();
                    reader.ReadEndElement();
                }

                return algorithm;
            }
            catch(Exception ex)
            {
                if (ex is XmlReadException)
                    throw;

                throw XmlUtil.LogReadException(LogMessages.IDX30016, ex, XmlSignatureConstants.Elements.Transform);
            }
        }

        /// <summary>
        /// Reads XML conforming to https://www.w3.org/TR/2001/PR-xmldsig-core-20010820/#sec-SignatureMethod
        /// </summary>
        /// <param name="reader">a <see cref="XmlReader"/>positioned on a &lt;SignatureMethod> element.</param>
        /// <exception cref="ArgumentNullException">if <paramref name="reader"/> is null.</exception>
        /// <exception cref="XmlReadException">if there is a problem reading the XML.</exception>
        /// <returns>A string with the signature method.</returns>
        public virtual string ReadSignatureMethod(XmlReader reader)
        {
            XmlUtil.CheckReaderOnEntry(reader, XmlSignatureConstants.Elements.SignatureMethod, XmlSignatureConstants.Namespace);

            try
            {
                bool isEmptyElement = reader.IsEmptyElement;
                var signatureMethod = reader.GetAttribute(XmlSignatureConstants.Attributes.Algorithm, null);
                if (signatureMethod == null)
                    throw XmlUtil.OnRequiredAttributeMissing(XmlSignatureConstants.Elements.SignatureMethod, XmlSignatureConstants.Attributes.Algorithm);

                reader.Read();
                reader.MoveToContent();
                if (!isEmptyElement)
                {
                    reader.MoveToContent();
                    reader.ReadEndElement();
                }

                return signatureMethod;
            }
            catch(Exception ex)
            {
                if (ex is XmlReadException)
                    throw;

                throw XmlUtil.LogReadException(LogMessages.IDX30016, ex, XmlSignatureConstants.Elements.Transform);
            }
        }

        /// <summary>
        /// Reads XML conforming to https://www.w3.org/TR/2001/PR-xmldsig-core-20010820/#sec-CanonicalizationMethod
        /// </summary>
        /// <param name="reader">a <see cref="XmlReader"/>positioned on a &lt;CanonicalizationMethod> element.</param>
        /// <exception cref="ArgumentNullException">if <paramref name="reader"/> is null.</exception>
        /// <exception cref="XmlReadException">if there is a problem reading the XML.</exception>
        /// <returns>A string with the canonicalization method.</returns>
        public virtual string ReadCanonicalizationMethod(XmlReader reader)
        {
            // <CanonicalizationMethod>
            XmlUtil.CheckReaderOnEntry(reader, XmlSignatureConstants.Elements.CanonicalizationMethod, XmlSignatureConstants.Namespace);

            try
            {
                bool isEmptyElement = reader.IsEmptyElement;
                var algorithm = reader.GetAttribute(XmlSignatureConstants.Attributes.Algorithm, null);
                if (string.IsNullOrEmpty(algorithm))
                    throw XmlUtil.LogReadException(LogMessages.IDX30013, XmlSignatureConstants.Elements.Signature, XmlSignatureConstants.Attributes.Algorithm);

                if (algorithm != SecurityAlgorithms.ExclusiveC14nWithComments && algorithm != SecurityAlgorithms.ExclusiveC14n)
                    throw XmlUtil.LogReadException(LogMessages.IDX30100, XmlSignatureConstants.Elements.Transform, algorithm, SecurityAlgorithms.ExclusiveC14n, SecurityAlgorithms.ExclusiveC14nWithComments);

                reader.Read();
                reader.MoveToContent();
                if (!isEmptyElement)
                {
                    if (reader.IsStartElement(XmlSignatureConstants.ExclusiveC14nInclusiveNamespaces))
                        throw XmlUtil.LogReadException(LogMessages.IDX30107);

                    reader.MoveToContent();
                    reader.ReadEndElement();
                }

                return algorithm;
            }
            catch(Exception ex)
            {
                if (ex is XmlReadException)
                    throw;

                throw XmlUtil.LogReadException(LogMessages.IDX30016, ex, XmlSignatureConstants.Elements.Transform);
            }
        }

        /// <summary>
        /// Writes the contents of a <see cref="KeyInfo"/> as XML conforming to https://www.w3.org/TR/2001/PR-xmldsig-core-20010820/#sec-KeyInfo.
        /// </summary>
        /// <param name="writer">the <see cref="XmlWriter"/> to use.</param>
        /// <param name="keyInfo">the <see cref="KeyInfo"/>to write.</param>
        /// <exception cref="ArgumentNullException">if <paramref name="writer"/> is null.</exception>
        /// <exception cref="ArgumentNullException">if <paramref name="keyInfo"/> is null.</exception>
        /// <exception cref="XmlWriteException">if there is a problem writing the XML.</exception>
        public virtual void WriteKeyInfo(XmlWriter writer, KeyInfo keyInfo)
        {
            if (writer == null)
                throw LogArgumentNullException(nameof(writer));

            if (keyInfo == null)
                throw LogArgumentNullException(nameof(keyInfo));

            // <KeyInfo>
            writer.WriteStartElement(PreferredPrefix, XmlSignatureConstants.Elements.KeyInfo, XmlSignatureConstants.Namespace);

            if (keyInfo.KeyName != null)
            {
                writer.WriteElementString(PreferredPrefix, XmlSignatureConstants.Elements.KeyName, XmlSignatureConstants.Namespace, keyInfo.KeyName);
            }

            if (keyInfo.RSAKeyValue != null)
            {
                // <KeyValue>
                writer.WriteStartElement(PreferredPrefix, XmlSignatureConstants.Elements.KeyValue, XmlSignatureConstants.Namespace);

                // <RSAKeyValue>
                writer.WriteStartElement(PreferredPrefix, XmlSignatureConstants.Elements.RSAKeyValue, XmlSignatureConstants.Namespace);

                // <Modulus>...</Modulus>
                writer.WriteElementString(PreferredPrefix, XmlSignatureConstants.Elements.Modulus, XmlSignatureConstants.Namespace, keyInfo.RSAKeyValue.Modulus);

                // <Exponent>...</Exponent>
                writer.WriteElementString(PreferredPrefix, XmlSignatureConstants.Elements.Exponent, XmlSignatureConstants.Namespace, keyInfo.RSAKeyValue.Exponent);

                // </RSAKeyValue>
                writer.WriteEndElement();

                // </KeyValue>
                writer.WriteEndElement();
            }

            if (keyInfo.RetrievalMethodUri != null)
            {
                writer.WriteStartElement(PreferredPrefix, XmlSignatureConstants.Elements.RetrievalMethod, XmlSignatureConstants.Namespace);
                writer.WriteAttributeString(XmlSignatureConstants.Attributes.URI, null, keyInfo.RetrievalMethodUri);
                writer.WriteEndElement();
            }

            foreach (var data in keyInfo.X509Data)
            {
                // <X509Data>
                writer.WriteStartElement(PreferredPrefix, XmlSignatureConstants.Elements.X509Data, XmlSignatureConstants.Namespace);

                if (data.IssuerSerial != null)
                {
                    writer.WriteStartElement(PreferredPrefix, XmlSignatureConstants.Elements.X509IssuerSerial, XmlSignatureConstants.Namespace);

                    writer.WriteElementString(PreferredPrefix, XmlSignatureConstants.Elements.X509IssuerName, XmlSignatureConstants.Namespace, data.IssuerSerial.IssuerName);

                    writer.WriteElementString(PreferredPrefix, XmlSignatureConstants.Elements.X509SerialNumber, XmlSignatureConstants.Namespace, data.IssuerSerial.SerialNumber);

                    writer.WriteEndElement();
                }

                if (data.SKI != null)
                {
                    writer.WriteElementString(PreferredPrefix, XmlSignatureConstants.Elements.X509SKI, XmlSignatureConstants.Namespace, data.SKI);

                }

                if (data.SubjectName != null)
                {
                    writer.WriteElementString(PreferredPrefix, XmlSignatureConstants.Elements.X509SubjectName, XmlSignatureConstants.Namespace, data.SubjectName);
                }

                foreach (var certificate in data.Certificates)
                {
                    // <X509Certificate>...</X509Certificate>
                    writer.WriteElementString(PreferredPrefix, XmlSignatureConstants.Elements.X509Certificate, XmlSignatureConstants.Namespace, certificate);
                }

                if (data.CRL != null)
                {
                    writer.WriteElementString(PreferredPrefix, XmlSignatureConstants.Elements.X509CRL, XmlSignatureConstants.Namespace, data.CRL);
                }

                // </X509Data>
                writer.WriteEndElement();
            }

            // </KeyInfo>
            writer.WriteEndElement();
        }

        /// <summary>
        /// Writes the contents of a <see cref="Reference"/> as XML conforming to https://www.w3.org/TR/2001/PR-xmldsig-core-20010820/#sec-Reference.
        /// </summary>
        /// <param name="writer">the <see cref="XmlWriter"/> to use.</param>
        /// <param name="reference">the <see cref="Reference"/>to write.</param>
        /// <remarks>Assumes the &lt;DigestValue> has been calculated, no canonicalization or digest calculation is performed.</remarks>
        /// <exception cref="ArgumentNullException">if <paramref name="writer"/> is null.</exception>
        /// <exception cref="ArgumentNullException">if <paramref name="reference"/> is null.</exception>
        /// <exception cref="XmlWriteException">if <see cref="Reference.DigestMethod"/> is null or empty.</exception>
        /// <exception cref="XmlWriteException">if <see cref="Reference.DigestValue"/> is null or empty.</exception>
        /// <exception cref="XmlWriteException">if one of the values in <see cref="Reference.Transforms"/> is null or empty.</exception>
        public virtual void WriteReference(XmlWriter writer, Reference reference)
        {
            if (writer == null)
                LogArgumentNullException(nameof(writer));

            if (reference == null)
                LogArgumentNullException(nameof(reference));

            if (string.IsNullOrEmpty(reference.DigestMethod))
                throw XmlUtil.LogWriteException(LogMessages.IDX30401, XmlSignatureConstants.Elements.Reference, XmlSignatureConstants.Elements.DigestMethod);

            if (string.IsNullOrEmpty(reference.DigestValue))
                throw XmlUtil.LogWriteException(LogMessages.IDX30401, XmlSignatureConstants.Elements.Reference, XmlSignatureConstants.Elements.DigestValue);

            // <Reference>
            writer.WriteStartElement(PreferredPrefix, XmlSignatureConstants.Elements.Reference, XmlSignatureConstants.Namespace);

            // @Id
            if (reference.Id != null)
                writer.WriteAttributeString(XmlSignatureConstants.Attributes.Id, null, reference.Id);

            // @Uri
            if (reference.Uri != null)
                writer.WriteAttributeString(XmlSignatureConstants.Attributes.URI, null, reference.Uri);
            else if (reference.Id != null)
                if (reference.Id.StartsWith("#"))
                    writer.WriteAttributeString(XmlSignatureConstants.Attributes.URI, null, reference.Id);
                else
                    writer.WriteAttributeString(XmlSignatureConstants.Attributes.URI, null, "#" + reference.Id);

            // @Type
            if (reference.Type != null)
                writer.WriteAttributeString(XmlSignatureConstants.Attributes.Type, null, reference.Type);

            // <Transforms>
            writer.WriteStartElement(PreferredPrefix, XmlSignatureConstants.Elements.Transforms, XmlSignatureConstants.Namespace);

            // <Transform>
            foreach (var transform in reference.Transforms)
            {
                if (string.IsNullOrEmpty(transform))
                    throw XmlUtil.LogWriteException(LogMessages.IDX30403);

                // <Transform>
                writer.WriteStartElement(PreferredPrefix, XmlSignatureConstants.Elements.Transform, XmlSignatureConstants.Namespace);

                // @Algorithm
                writer.WriteAttributeString(XmlSignatureConstants.Attributes.Algorithm, transform);

                // </Transform>
                writer.WriteEndElement();
            }
            
            // </Transforms>
            writer.WriteEndElement();

            // <DigestMethod>
            writer.WriteStartElement(PreferredPrefix, XmlSignatureConstants.Elements.DigestMethod, XmlSignatureConstants.Namespace);

            // @Algorithm
            writer.WriteAttributeString(XmlSignatureConstants.Attributes.Algorithm, null, reference.DigestMethod);

            // </DigestMethod>
            writer.WriteEndElement();

            // <DigestValue />
            writer.WriteElementString(PreferredPrefix, XmlSignatureConstants.Elements.DigestValue, XmlSignatureConstants.Namespace, reference.DigestValue);

            // </Reference>
            writer.WriteEndElement();
        }

        /// <summary>
        /// Writes the contents of a <see cref="Signature"/> as XML conforming to https://www.w3.org/TR/2001/PR-xmldsig-core-20010820/#sec-Signature.
        /// </summary>
        /// <param name="writer">the <see cref="XmlWriter"/> to use.</param>
        /// <param name="signature">the <see cref="Signature"/>to write.</param>
        /// <remarks>Assumes the &lt;SignatureValue> has been calculated, no canonicalization or signature calculation is performed.</remarks>
        /// <exception cref="ArgumentNullException">if <paramref name="writer"/> is null.</exception>
        /// <exception cref="ArgumentNullException">if <paramref name="signature"/> is null.</exception>
        /// <exception cref="XmlWriteException">if <see cref="Signature.SignatureValue"/> is null or empty.</exception>
        /// <exception cref="XmlWriteException">if <see cref="Signature.SignedInfo"/> is null.</exception>
        /// <exception cref="XmlWriteException">if one of the values in <see cref="Reference.Transforms"/> is null or empty.</exception>
        public virtual void WriteSignature(XmlWriter writer, Signature signature)
        {
            if (writer == null)
                LogArgumentNullException(nameof(writer));

            if (signature == null)
                LogArgumentNullException(nameof(signature));

            if (string.IsNullOrEmpty(signature.SignatureValue))
                throw XmlUtil.LogWriteException(LogMessages.IDX30401, XmlSignatureConstants.Elements.Signature, XmlSignatureConstants.Elements.SignatureValue);

            if (signature.SignedInfo == null)
                throw XmlUtil.LogWriteException(LogMessages.IDX30404);

            // <Signature>
            writer.WriteStartElement(PreferredPrefix, XmlSignatureConstants.Elements.Signature, XmlSignatureConstants.Namespace);
            if (signature.Id != null)
                writer.WriteAttributeString(XmlSignatureConstants.Attributes.Id, null, signature.Id);

            // <SignedInfo>
            WriteSignedInfo(writer, signature.SignedInfo);

            // <SignatureValue>
            writer.WriteStartElement(PreferredPrefix, XmlSignatureConstants.Elements.SignatureValue, XmlSignatureConstants.Namespace);

            // TODO - need signature value id
            // @Id
            if (!string.IsNullOrEmpty(signature.Id))
                writer.WriteAttributeString(XmlSignatureConstants.Attributes.Id, null, signature.Id);

            writer.WriteString(signature.SignatureValue);

            // </ SignatureValue>
            writer.WriteEndElement();

            // <KeyInfo>
            //signature.KeyInfo = new KeyInfo(signature.SigningCredentials.Key);
            if (signature.KeyInfo != null)
                WriteKeyInfo(writer, signature.KeyInfo);

            // </ Signature>
            writer.WriteEndElement();
        }

        /// <summary>
        /// Writes the contents of a <see cref="SignedInfo"/> as XML conforming to https://www.w3.org/TR/2001/PR-xmldsig-core-20010820/#sec-SignedInfo.
        /// </summary>
        /// <param name="writer">the <see cref="XmlWriter"/> to use.</param>
        /// <param name="signedInfo">the <see cref="SignedInfo"/>to write.</param>
        /// <remarks>Assumes the &lt;Reference> digest has been calculated, no canonicalization or digest calculation is performed.</remarks>
        /// <exception cref="ArgumentNullException">if <paramref name="writer"/> is null.</exception>
        /// <exception cref="ArgumentNullException">if <paramref name="signedInfo"/> is null.</exception>
        /// <exception cref="XmlWriteException">if <see cref="SignedInfo.CanonicalizationMethod"/> is null or empty.</exception>
        /// <exception cref="XmlWriteException">if <see cref="SignedInfo.References"/> is null.</exception>
        /// <exception cref="NotSupportedException">if <see cref="SignedInfo.References" />.Count > 1.</exception>
        /// <exception cref="XmlWriteException">if <see cref="SignedInfo.SignatureMethod"/> is null or empty.</exception>
        public virtual void WriteSignedInfo(XmlWriter writer, SignedInfo signedInfo)
        {
            if (writer == null)
                LogArgumentNullException(nameof(writer));

            if (signedInfo == null)
                LogArgumentNullException(nameof(signedInfo));

            if (string.IsNullOrEmpty(signedInfo.CanonicalizationMethod))
                throw XmlUtil.LogWriteException(LogMessages.IDX30401, XmlSignatureConstants.Elements.SignedInfo, XmlSignatureConstants.Elements.CanonicalizationMethod);

            if (string.IsNullOrEmpty(signedInfo.SignatureMethod))
                throw XmlUtil.LogWriteException(LogMessages.IDX30401, XmlSignatureConstants.Elements.SignedInfo, XmlSignatureConstants.Elements.SignatureMethod);

            if (signedInfo.References == null)
                throw XmlUtil.LogWriteException(LogMessages.IDX30405);

            // <SignedInfo>
            writer.WriteStartElement(PreferredPrefix, XmlSignatureConstants.Elements.SignedInfo, XmlSignatureConstants.Namespace);

            // @Id
            if (signedInfo.Id != null)
                writer.WriteAttributeString(XmlSignatureConstants.Attributes.Id, null, signedInfo.Id);

            // <CanonicalizationMethod>
            writer.WriteStartElement(PreferredPrefix, XmlSignatureConstants.Elements.CanonicalizationMethod, XmlSignatureConstants.Namespace);
            
            //@Algorithm
            writer.WriteAttributeString(XmlSignatureConstants.Attributes.Algorithm, null, signedInfo.CanonicalizationMethod);
            writer.WriteEndElement();

            // <SignatureMethod>
            writer.WriteStartElement(PreferredPrefix, XmlSignatureConstants.Elements.SignatureMethod, XmlSignatureConstants.Namespace);
            
            // @Algorithm
            writer.WriteAttributeString(XmlSignatureConstants.Attributes.Algorithm, null, signedInfo.SignatureMethod);

            // </SignatureMethod>
            writer.WriteEndElement();

            // <Reference>
            foreach(var reference in signedInfo.References)
                WriteReference(writer, reference);

            // </SignedInfo>
            writer.WriteEndElement();
        }
    }
}
