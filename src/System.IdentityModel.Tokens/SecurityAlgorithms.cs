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

namespace System.IdentityModel.Tokens
{
    public static class SecurityAlgorithms
    {
        public const string Aes128Encryption = "http://www.w3.org/2001/04/xmlenc#aes128-cbc";
        public const string Aes128KeyWrap = "http://www.w3.org/2001/04/xmlenc#kw-aes128";
        public const string Aes192Encryption = "http://www.w3.org/2001/04/xmlenc#aes192-cbc";
        public const string Aes192KeyWrap = "http://www.w3.org/2001/04/xmlenc#kw-aes192";
        public const string Aes256Encryption = "http://www.w3.org/2001/04/xmlenc#aes256-cbc";
        public const string Aes256KeyWrap = "http://www.w3.org/2001/04/xmlenc#kw-aes256";
        public const string DesEncryption = "http://www.w3.org/2001/04/xmlenc#des-cbc";

        public const string ExclusiveC14n = "http://www.w3.org/2001/10/xml-exc-c14n#";
        public const string ExclusiveC14nWithComments = "http://www.w3.org/2001/10/xml-exc-c14n#WithComments";
        public const string HmacSha256Signature = "http://www.w3.org/2001/04/xmldsig-more#hmac-sha256";
        public const string HmacSha384Signature = "http://www.w3.org/2001/04/xmldsig-more#hmac-sha384";
        public const string HmacSha512Signature = "http://www.w3.org/2001/04/xmldsig-more#hmac-sha512";

        public const string Ripemd160Digest = "http://www.w3.org/2001/04/xmlenc#ripemd160";
        public const string RsaOaepKeyWrap = "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p";
        public const string RsaSha256Signature = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
        public const string RsaSha384Signature = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384";
        public const string RsaSha512Signature = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512";

        public const string RsaV15KeyWrap = "http://www.w3.org/2001/04/xmlenc#rsa-1_5";

        public const string Sha256Digest = "http://www.w3.org/2001/04/xmlenc#sha256";
        public const string Sha512Digest = "http://www.w3.org/2001/04/xmlenc#sha512";

        public const string ECDSA_SHA256 = "ES256";
        public const string ECDSA_SHA384 = "ES384";
        public const string ECDSA_SHA512 = "ES512";
        public const string HMAC_SHA256 = "HS256";
        public const string HMAC_SHA384 = "HS384";
        public const string HMAC_SHA512 = "HS512";
        public const string NONE = "none";
        public const string RSA_SHA256 = "RS256";
        public const string RSA_SHA384 = "RS384";
        public const string RSA_SHA512 = "RS512";
        public const string SHA256 = "SHA256";
        public const string SHA384 = "SHA384";
        public const string SHA512 = "SHA512";
        public const string PS256 = "PS256";
        public const string PS384 = "PS384";
        public const string PS512 = "PS512";
    }
}
