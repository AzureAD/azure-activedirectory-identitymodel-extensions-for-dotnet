using System;

namespace Microsoft.IdentityModel.Protocols
{
    /// <summary>
    /// Names for Json Web Key Values
    /// </summary>
    public static class JsonWebKeyParameterNames
    {
#pragma warning disable 1591
        public const string Alg = "alg";
        public const string Crv = "crv";
        public const string D = "d";
        public const string DP = "dp";
        public const string DQ = "dq";
        public const string E = "e";
        public const string K = "k";
        public const string KeyOps = "key_ops";
        public const string Keys = "keys";
        public const string Kid = "kid";
        public const string Kty = "kty";
        public const string N = "n";
        public const string Oth = "oth";
        public const string P = "p";
        public const string Q = "q";
        public const string R = "r";
        public const string T = "t";
        public const string QI = "qi";
        public const string Use = "use";
        public const string X5c = "x5c";
        public const string X5t = "x5t";
        public const string X5tS256 = "x5t#S256";
        public const string X5u = "x5u";
        public const string X = "x";
        public const string Y = "y";
#pragma warning restore 1591
    }

    /// <summary>
    /// Constants for JsonWebKeyUse (sec 4.2)
    /// http://tools.ietf.org/html/draft-ietf-jose-json-web-key-27#section-4
    /// </summary>
    public static class JsonWebKeyUseNames
    {
#pragma warning disable 1591
        public const string Sig = "sig";
        public const string Enc = "enc";
#pragma warning restore 1591
    }

    /// <summary>
    /// Constants for JsonWebAlgorithms  "kty" Key Type (sec 6.1)
    /// http://tools.ietf.org/html/draft-ietf-jose-json-web-algorithms-27#section-6.1
    /// </summary>
    public static class JsonWebAlgorithmsKeyTypes
    {
#pragma warning disable 1591
        public const string EllipticCurve = "EC";
        public const string RSA = "RSA";
        public const string Octet = "oct";
#pragma warning restore 1591
    }
}
