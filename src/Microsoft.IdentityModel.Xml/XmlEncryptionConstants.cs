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

#if EncryptedTokens

namespace Microsoft.IdentityModel.Xml
{
    /// <summary>
    /// Constants for XML Encryption.
    /// Definitions for namespace, attributes and elements as defined in http://www.w3.org/TR/2002/REC-xmlenc-core-2002120
    /// </summary>
    public static class XmlEncryptionConstants
    {
#pragma warning disable 1591
        public const string Namespace = "http://www.w3.org/2001/04/xmlenc#";
        public const string Prefix = "xenc";

        public static class Attributes
        {
            public const string Algorithm = "Algorithm";
            public const string Encoding = "Encoding";
            public const string Id = "Id";
            public const string MimeType = "MimeType";
            public const string Recipient = "Recipient";
            public const string Type = "Type";
            public const string Uri = "URI";
        }

        public static class Elements
        {
            public const string CarriedKeyName = "CarriedKeyName";
            public const string CipherData = "CipherData";
            public const string CipherReference = "CiperReference";
            public const string CipherValue = "CipherValue";
            public const string DataReference = "DataReference";
            public const string EncryptedData = "EncryptedData";
            public const string EncryptedKey = "EncryptedKey";
            public const string EncryptionMethod = "EncryptionMethod";
            public const string EncryptionProperties = "EncryptionProperties";
            public const string KeyReference = "KeyReference";
            public const string KeySize = "KeySize";
            public const string OaepParams = "OAEPparams";
            public const string Recipient = "Recipient";
            public const string ReferenceList = "ReferenceList";
        }

        public static class EncryptedDataTypes
        {
            public const string Element = Namespace + "Element";
            public const string Content = Namespace + "Content";
#pragma warning restore 1591
        }
    }
}
#endif