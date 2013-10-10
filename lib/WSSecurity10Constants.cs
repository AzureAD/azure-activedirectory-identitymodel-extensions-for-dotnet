//------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
//------------------------------------------------------------

namespace System.IdentityModel.Tokens
{
    /// <summary>
    /// Defines constants needed from WS-Security 1.0.
    /// </summary>
    internal static class WSSecurity10Constants
    {
#pragma warning disable 1591
        public const string Namespace           = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd";
        public const string Prefix              = "wsse";
        public const string Base64EncodingType  = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary";
        public const string Base64Binary        = "Base64Binary";
        public const string Base64BinaryLower   = "base64Binary";

        public static class Attributes
        {
            public const string ValueType           = "ValueType";
            public const string EncodingType        = "EncodingType";
            public const string EncodingTypeLower   = "encodingType";
        }

        public static class Elements
        {
            public const string BinarySecurityToken    = "BinarySecurityToken";
        }
#pragma warning restore 1591
    }
}
