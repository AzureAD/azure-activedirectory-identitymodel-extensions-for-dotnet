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

namespace Microsoft.IdentityModel.Protocols.XmlEnc
{
    /// <summary>
    /// Constants for XML Encryption element names.
    /// <para>see: https://www.w3.org/TR/xmlenc-core1/ </para>
    /// </summary>
    internal static class XmlEncryptionElements
    {
        /// <summary>
        /// Gets the value for "CarriedKeyName"
        /// </summary>
        public const string CarriedKeyName = "CarriedKeyName";

        /// <summary>
        /// Gets the value for "CipherData"
        /// </summary>
        public const string CipherData = "CipherData";

        /// <summary>
        /// Gets the value for "CipherReference"
        /// </summary>
        public const string CipherReference = "CipherReference";

        /// <summary>
        /// Gets the value for "CipherValue"
        /// </summary>
        public const string CipherValue = "CipherValue";

        /// <summary>
        /// Gets the value for "DataReference"
        /// </summary>
        public const string DataReference = "DataReference";

        /// <summary>
        /// Gets the value for "EncryptedData"
        /// </summary>
        public const string EncryptedData = "EncryptedData";

        /// <summary>
        /// Gets the value for "EncryptedKey"
        /// </summary>
        public const string EncryptedKey = "EncryptedKey";

        /// <summary>
        /// Gets the value for "EncryptionMethod"
        /// </summary>
        public const string EncryptionMethod = "EncryptionMethod";

        /// <summary>
        /// Gets the value for "EncryptionProperties"
        /// </summary>
        public const string EncryptionProperties = "EncryptionProperties";

        /// <summary>
        /// Gets the value for "KeyReference"
        /// </summary>
        public const string KeyReference = "KeyReference";

        /// <summary>
        /// Gets the value for "KeySize"
        /// </summary>
        public const string KeySize = "KeySize";

        /// <summary>
        /// Gets the value for "OaepParams"
        /// </summary>
        public const string OaepParams = "OaepParams";

        /// <summary>
        /// Gets the value for "Recipient"
        /// </summary>
        public const string Recipient = "Recipient";

        /// <summary>
        /// Gets the value for "ReferenceList"
        /// </summary>
        public const string ReferenceList = "ReferenceList";
    }
}
