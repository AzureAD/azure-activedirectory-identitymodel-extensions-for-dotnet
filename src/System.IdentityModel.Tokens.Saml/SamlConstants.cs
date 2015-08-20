//-----------------------------------------------------------------------
// Copyright (c) Microsoft Open Technologies, Inc.
// All Rights Reserved
// Apache License 2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// 
// http://www.apache.org/licenses/LICENSE-2.0
// 
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//-----------------------------------------------------------------------

namespace System.IdentityModel.Tokens.Saml
{
    /// <summary>
    /// Constants related to SAML Tokens.
    /// </summary>
    public static class SamlConstants
    {
        #pragma warning disable 1591
        public const string Assertion = "Assertion";
        public const string EncryptedAssertion = "EncryptedAssertion";
        public const int MajorVersionValue = 1;
        public const int MinorVersionValue = 1;
        public const string Prefix = "saml";
        public const string Saml11Namespace = "urn:oasis:names:tc:SAML:1.0:assertion";
        public const string Saml2Namespace = "urn:oasis:names:tc:SAML:2.0:assertion";
        #pragma warning restore 1591
    }
}
