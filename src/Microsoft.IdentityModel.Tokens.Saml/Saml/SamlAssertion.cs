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
using System.Collections.ObjectModel;
using System.IO;
using System.Xml;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Xml;

namespace Microsoft.IdentityModel.Tokens.Saml
{
    public class SamlAssertion //: ICanonicalWriterEndRootElementCallback
    {
        private string _assertionId = SamlConstants.AssertionIdPrefix + Guid.NewGuid().ToString();
        private string _issuer;
        private Collection<SamlStatement> _statements = new Collection<SamlStatement>();
        private XmlTokenStream _tokenStream;
        private XmlTokenStream _sourceData;

        public SamlAssertion() { }

        public SamlAssertion(
            string assertionId,
            string issuer,
            DateTime issueInstant,
            SamlConditions samlConditions,
            SamlAdvice samlAdvice,
            IEnumerable<SamlStatement> samlStatements
            )
        {
            if (string.IsNullOrEmpty(assertionId))
                throw LogHelper.LogArgumentNullException(nameof(assertionId));

            _tokenStream = new XmlTokenStream();

            // TODO warning
            //if (!IsAssertionIdValid(assertionId))
            //    throw LogHelper.ExceptionUtility.ThrowHelperArgument(SR.GetString(SR.SAMLAssertionIDIsInvalid, assertionId));

            if (string.IsNullOrEmpty(issuer))
                throw LogHelper.LogArgumentNullException(nameof(issuer));

            if (samlStatements == null)
                throw LogHelper.LogArgumentNullException(nameof(samlStatements));

            AssertionId = assertionId;
            Issuer = issuer;
            IssueInstant = issueInstant.ToUniversalTime();
            Conditions = samlConditions;
            Advice = samlAdvice;

            foreach (SamlStatement samlStatement in samlStatements)
            {
                if (samlStatement == null)
                    throw LogHelper.LogArgumentNullException("SAMLEntityCannotBeNullOrEmpty");

                _statements.Add(samlStatement);
            }

            if (_statements.Count == 0)
                throw LogHelper.LogExceptionMessage(new ArgumentException("SAMLAssertionRequireOneStatement"));
        }

        public SecurityKey SecurityKey { get; set; }

        public int MinorVersion
        {
            get { return SamlConstants.MinorVersionValue; }
        }

        public int MajorVersion
        {
            get { return SamlConstants.MajorVersionValue; }
        }

        public string AssertionId
        {
            get { return _assertionId; }
            set
            {
                if (string.IsNullOrEmpty(value))
                    throw LogHelper.LogArgumentNullException(nameof(value));

                _assertionId = value;
            }
        }

        /// <summary>
        /// Indicates whether this assertion was deserialized from XML source
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
        /// <returns></returns>
        public virtual bool CanWriteSourceData
        {
            get { return null != _sourceData; }
        }

        public string Issuer
        {
            get { return _issuer; }
            set
            {
                if (string.IsNullOrEmpty(value))
                    throw LogHelper.LogArgumentNullException(nameof(value));

                _issuer = value;
            }
        }

        public DateTime IssueInstant { get; set; } = DateTime.UtcNow;

        public SamlConditions Conditions { get; set; }

        public SamlAdvice Advice { get; set; }

        public IList<SamlStatement> Statements
        {
            get
            {
                return _statements;
            }
        }

        public SigningCredentials SigningCredentials { get; set; }

        public Signature Signature { get; set; }

        public SecurityKey SignatureVerificationKey { get; set; }

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
        /// <param name="reader"></param>
        internal virtual void CaptureSourceData(EnvelopedSignatureReader reader)
        {
            if (null == reader)
                throw LogHelper.LogArgumentNullException(nameof(reader));

            // TODO capturing of tokens, where to do this
            _sourceData = reader.XmlTokens;
        }

        bool IsAssertionIdValid(string assertionId)
        {
            if (string.IsNullOrEmpty(assertionId))
                return false;

            // The first character of the Assertion ID should be a letter or a '_'
            return (((assertionId[0] >= 'A') && (assertionId[0] <= 'Z')) ||
                ((assertionId[0] >= 'a') && (assertionId[0] <= 'z')) ||
                (assertionId[0] == '_'));
        }

    }
}
