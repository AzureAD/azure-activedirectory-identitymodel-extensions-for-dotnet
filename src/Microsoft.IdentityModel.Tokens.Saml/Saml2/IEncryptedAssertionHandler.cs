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

using System.Xml;

namespace Microsoft.IdentityModel.Tokens.Saml2
{
    /// <summary>
    /// Exposes operations for interactions with a <see cref="Saml2EncryptedAssertion"/>.
    /// </summary>
    public interface IEncryptedAssertionHandler
    {
        /// <summary>
        /// Encrypts provided SAML2 <paramref name="assertionData"/> bytes using the <paramref name="encryptingCredentials"/> instance.
        /// </summary>
        /// <param name="assertionData">SAML2 assertion bytes to be encrypted.</param>
        /// <param name="encryptingCredentials">An ecryption credentials instance.</param>
        /// <returns>A <see cref="Saml2EncryptedAssertion"/> instance.</returns>
        Saml2EncryptedAssertion EncryptAssertion(byte[] assertionData, EncryptingCredentials encryptingCredentials);

        /// <summary>
        /// Decrypts provided <paramref name="assertion"/> using the <paramref name="validationParameters"/> instance.
        /// </summary>
        /// <param name="assertion">A <see cref="Saml2EncryptedAssertion"/> instance to be decrypted.</param>
        /// <param name="validationParameters">A <see cref="TokenValidationParameters"/> instance to be used to decrypt <paramref name="assertion"/>.</param>
        /// <param name="assertionString">A string representation of an <paramref name="assertion"/>.</param>
        /// <returns>A Saml2 assertion string.</returns>
        string DecryptAssertion(Saml2EncryptedAssertion assertion, TokenValidationParameters validationParameters, string assertionString);

        /// <summary>
        /// Reads provided SAML2 <paramref name="assertion"/> string into a <see cref="Saml2EncryptedAssertion"/> instance.
        /// </summary>
        /// <param name="assertion">A SAML2 assertion string.</param>
        /// <returns>A <see cref="Saml2EncryptedAssertion"/> instance.</returns>
        Saml2EncryptedAssertion ReadEncryptedAssertion(string assertion);

        /// <summary>
        /// Writes provided <paramref name="assertion"/> into the <paramref name="writer"/>.
        /// </summary>
        /// <param name="writer">An XML writer instance.</param>
        /// <param name="assertion">A <see cref="Saml2EncryptedAssertion"/> instance to be writen into an XML writer.</param>
        /// <param name="samlPrefix"> A saml2 xml prefix.</param>
        void WriteAssertionToXml(XmlWriter writer, Saml2EncryptedAssertion assertion, string samlPrefix);
    }
}
