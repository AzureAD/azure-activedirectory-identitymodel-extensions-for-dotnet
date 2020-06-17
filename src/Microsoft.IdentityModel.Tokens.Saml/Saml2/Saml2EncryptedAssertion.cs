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

using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Xml;
using System.Xml;

namespace Microsoft.IdentityModel.Tokens.Saml2
{
    /// <summary>
    /// Represents the <see cref="Saml2EncryptedAssertion"/> element.
    /// </summary>
    public class Saml2EncryptedAssertion
    {
        /// <summary>
        /// Represents the <see cref="EncryptedData"/> element in XML encryption.
        /// </summary>
        public EncryptedData EncryptedData { get; set; }

        /// <summary>
        /// Represents the <see cref="EncryptedKey"/> element in XML encryption.
        /// </summary>
        public EncryptedKey EncryptedKey { get; set; }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="reader"></param>
        public virtual void ReadXml(XmlDictionaryReader reader)
        {
            if (reader == null)
                throw LogHelper.LogArgumentNullException(nameof(reader));

            if (!(reader.IsStartElement(Saml2Constants.Elements.EncryptedAssertion, Saml2Constants.Namespace)))
                throw LogHelper.LogExceptionMessage(new Saml2SecurityTokenEncryptedAssertionDecryptionException(LogHelper.FormatInvariant(LogMessages.IDX13620, Saml2Constants.Elements.EncryptedAssertion, reader.Name)));

            reader.ReadStartElement();

            EncryptedData = new EncryptedData();
            EncryptedData.ReadXml(reader);

            if (IsReaderPointingToEncryptedKey(reader))
            {
                EncryptedKey = new EncryptedKey();
                EncryptedKey.ReadXml(reader);
            }
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="writer"></param>
        public virtual void WriteXml(XmlWriter writer)
        {
            if (writer == null)
                throw LogHelper.LogArgumentNullException(nameof(writer));

            EncryptedData.WriteXml(writer);

            if (EncryptedKey != null)
                EncryptedKey.WriteXml(writer);
        }

        private bool IsReaderPointingToEncryptedKey(XmlDictionaryReader reader)
        {
            if (reader == null)
                throw LogHelper.LogArgumentNullException(nameof(reader));

            if (reader.IsStartElement(XmlEncryptionConstants.Elements.EncryptedKey, XmlEncryptionConstants.Namespace))
                return true;

            return false;
        }
    }
}