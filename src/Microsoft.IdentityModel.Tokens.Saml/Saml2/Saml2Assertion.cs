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
using Microsoft.IdentityModel.Xml;
using static Microsoft.IdentityModel.Logging.LogHelper;

namespace Microsoft.IdentityModel.Tokens.Saml2
{
    /// <summary>
    /// Represents the Assertion element specified in [Saml2Core, 2.3.3].
    /// </summary>
    public class Saml2Assertion
    {
        private Saml2Id _id;
        private DateTime _issueInstant;
        private Saml2NameIdentifier _issuer;

        /// <summary>
        /// Creates an instance of a Saml2Assertion.
        /// </summary>
        /// <param name="issuer">Issuer of the assertion.</param>
        public Saml2Assertion(Saml2NameIdentifier issuer)
        {
            // TODO do we need issuer?
            Id = new Saml2Id();
            IssueInstant = DateTime.UtcNow;
            Issuer = issuer;
            Statements = new List<Saml2Statement>();
            Version = Saml2Constants.Version;
        }

        /// <summary>
        /// Gets or sets the <see cref="Signature"/> on the Assertion.
        /// </summary>
        public Signature Signature { get; set; }

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
        /// Gets or sets the <see cref="Saml2Id"/> identifier for this assertion. [Saml2Core, 2.3.3]
        /// </summary>
        public Saml2Id Id
        {
            get { return _id; }
            set
            {
                _id = value ?? throw LogArgumentNullException(nameof(value));
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
                _issuer = value ?? throw LogArgumentNullException(nameof(value));
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
        public ICollection<Saml2Statement> Statements
        {
            get;
        }

        /// <summary>
        /// Gets the version of this assertion. [Saml2Core, 2.3.3]
        /// </summary>
        /// <remarks>
        /// In this version of the Windows Identity Foundation, only version "2.0" is supported.
        /// </remarks>
        public string Version
        {
            get;
        }
    }
}
