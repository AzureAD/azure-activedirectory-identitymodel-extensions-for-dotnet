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
using System.Collections.ObjectModel;
using System.Xml;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Xml;

namespace Microsoft.IdentityModel.Tokens.Saml2
{
    /// <summary>
    /// Represents the Assertion element specified in [Saml2Core, 2.3.3].
    /// </summary>
    public class Saml2Assertion
    {
        private Collection<SecurityKeyIdentifierClause> _externalEncryptedKeys = new Collection<SecurityKeyIdentifierClause>();
        private Saml2Id _id = new Saml2Id();
        private DateTime _issueInstant = DateTime.UtcNow;
        private Saml2NameIdentifier _issuer;
        private XmlTokenStream _sourceData;
        private Collection<Saml2Statement> _statements = new Collection<Saml2Statement>();
        private string _version = "2.0";

        /// <summary>
        /// Creates an instance of a Saml2Assertion.
        /// </summary>
        /// <param name="issuer">Issuer of the assertion.</param>
        public Saml2Assertion(Saml2NameIdentifier issuer)
        {
            if (issuer == null)
                throw LogHelper.LogArgumentNullException(nameof(issuer));

            _issuer = issuer;
        }

        public SignedXml SignedXml { get; set; }

        /// <summary>
        /// Gets or sets additional information related to the assertion that assists processing in certain
        /// situations but which may be ignored by applications that do not understand the 
        /// advice or do not wish to make use of it. [Saml2Core, 2.3.3]
        /// </summary>
        public Saml2Advice Advice
        {
            get; set;
        }

        /// <summary>
        /// Gets a value indicating whether this assertion was deserialized from XML source
        /// and can re-emit the XML data unchanged.
        /// </summary>
        /// <remarks>
        /// <para>
        /// The default implementation preserves the source data when read using
        /// Saml2AssertionSerializer.ReadAssertion and is willing to re-emit the
        /// original data as long as the Id has not changed from the time that 
        /// assertion was read.
        /// </para>
        /// <para>
        /// Note that it is vitally important that SAML assertions with different
        /// data have different IDs. If implementing a scheme whereby an assertion
        /// "template" is loaded and certain bits of data are filled in, the Id 
        /// must be changed.
        /// </para>
        /// </remarks>
        /// <returns>'True' if this instance can write the source data.</returns>
        public virtual bool CanWriteSourceData
        {
            get { return null != _sourceData; }
        }

        /// <summary>
        /// Gets or sets conditions that must be evaluated when assessing the validity of and/or
        /// when using the assertion. [Saml2Core 2.3.3]
        /// </summary>
        public Saml2Conditions Conditions
        {
            get; set;
        }

        /// <summary>
        /// Gets or sets the credentials used for encrypting the assertion. The key
        /// identifier in the encrypting credentials will be used for the 
        /// embedded EncryptedKey in the EncryptedData element.
        /// </summary>
        public EncryptingCredentials EncryptingCredentials
        {
            get; set;
        }

        /// <summary>
        /// Gets additional encrypted keys which will be specified external to the 
        /// EncryptedData element, as children of the EncryptedAssertion element.
        /// </summary>
        public Collection<SecurityKeyIdentifierClause> ExternalEncryptedKeys
        {
            get { return _externalEncryptedKeys; }
        }

        /// <summary>
        /// Gets or sets the <see cref="Saml2Id"/> identifier for this assertion. [Saml2Core, 2.3.3]
        /// </summary>
        public Saml2Id Id
        {
            get { return _id; }
            set
            {
                if (null == value)
                    throw LogHelper.LogArgumentNullException(nameof(value));

                _id = value;
                _sourceData = null;
            }
        }

        /// <summary>
        /// Gets or sets the time instant of issue in UTC. [Saml2Core, 2.3.3]
        /// </summary>
        public DateTime IssueInstant
        {
            get { return _issueInstant; }
            set { _issueInstant = DateTimeUtil.ToUniversalTime(value); }
        }

        /// <summary>
        /// Gets or sets the <see cref="Saml2NameIdentifier"/> as the authority that is making the claim(s) in the assertion. [Saml2Core, 2.3.3]
        /// </summary>
        public Saml2NameIdentifier Issuer
        {
            get { return _issuer; }
            set
            {
                if (value == null)
                    throw LogHelper.LogArgumentNullException(nameof(value));

                _issuer = value;
            }
        }

        /// <summary>
        /// Gets or sets the <see cref="SigningCredentials"/> used by the issuer to protect the integrity of the assertion.
        /// </summary>
        public SigningCredentials SigningCredentials
        {
            get; set;
        }

        /// <summary>
        /// Gets or sets the <see cref="Saml2Subject"/> of the statement(s) in the assertion. [Saml2Core, 2.3.3]
        /// </summary>
        public Saml2Subject Subject
        {
            get; set;
        }

        /// <summary>
        /// Gets the <see cref="Saml2Statement"/>(s) regarding the subject.
        /// </summary>
        public Collection<Saml2Statement> Statements
        {
            get { return _statements; }
        }

        /// <summary>
        /// Gets the version of this assertion. [Saml2Core, 2.3.3]
        /// </summary>
        /// <remarks>
        /// In this version of the Windows Identity Foundation, only version "2.0" is supported.
        /// </remarks>
        public string Version
        {
            get { return _version; }
        }

        /// <summary>
        /// Writes the source data, if available.
        /// </summary>
        /// <exception cref="InvalidOperationException">When no source data is available</exception>
        /// <param name="writer">A <see cref="XmlWriter"/> for writting the data.</param>
        public virtual void WriteSourceData(XmlWriter writer)
        {
            if (!CanWriteSourceData)
                throw LogHelper.LogExceptionMessage(new Saml2SecurityTokenException("SR.ID4140"));

            // This call will properly just reuse the existing writer if it already qualifies
            _sourceData.SetElementExclusion(null, null);
            _sourceData.GetWriter().WriteTo(XmlDictionaryWriter.CreateDictionaryWriter(writer));
        }

        /// <summary>
        /// Captures the XML source data from an EnvelopedSignatureReader. 
        /// </summary>
        /// <remarks>
        /// The EnvelopedSignatureReader that was used to read the data for this
        /// assertion should be passed to this method after the &lt;/Assertion>
        /// element has been read. This method will preserve the raw XML data
        /// that was read, including the signature, so that it may be re-emitted
        /// without changes and without the need to re-sign the data. See 
        /// CanWriteSourceData and WriteSourceData.
        /// </remarks>
        /// <param name="reader"><see cref="EnvelopedSignatureReader"/> that contains the data for the assertion.</param>
        internal virtual void CaptureSourceData(EnvelopedSignatureReader reader)
        {
            if (null == reader)
                throw LogHelper.LogArgumentNullException(nameof(reader));

            _sourceData = reader.XmlTokens;
        }
    }
}
