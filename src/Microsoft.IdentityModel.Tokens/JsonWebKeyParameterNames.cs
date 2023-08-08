// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System.Text;

namespace Microsoft.IdentityModel.Tokens
{
#pragma warning disable 1591

    /// <summary>
    /// JsonWebKey parameter names
    /// </summary>
    public static class JsonWebKeyParameterNames
    {
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
        public const string QI = "qi";
        public const string Use = "use";
        public const string X = "x";
        public const string X5c = "x5c";
        public const string X5t = "x5t";
        public const string X5tS256 = "x5t#S256";
        public const string X5u = "x5u";
        public const string Y = "y";
    }

    internal static class JsonWebKeyParameterUtf8Bytes
    {
        public static readonly byte[] Alg = Encoding.UTF8.GetBytes("alg");
        public static readonly byte[] Crv = Encoding.UTF8.GetBytes("crv");
        public static readonly byte[] D = Encoding.UTF8.GetBytes("d");
        public static readonly byte[] DP = Encoding.UTF8.GetBytes("dp");
        public static readonly byte[] DQ = Encoding.UTF8.GetBytes("dq");
        public static readonly byte[] E = Encoding.UTF8.GetBytes("e");
        public static readonly byte[] K = Encoding.UTF8.GetBytes("k");
        public static readonly byte[] KeyOps = Encoding.UTF8.GetBytes("key_ops");
        public static readonly byte[] Keys = Encoding.UTF8.GetBytes("keys");
        public static readonly byte[] Kid = Encoding.UTF8.GetBytes("kid");
        public static readonly byte[] Kty = Encoding.UTF8.GetBytes("kty");
        public static readonly byte[] N = Encoding.UTF8.GetBytes("n");
        public static readonly byte[] Oth = Encoding.UTF8.GetBytes("oth");
        public static readonly byte[] P = Encoding.UTF8.GetBytes("p");
        public static readonly byte[] Q = Encoding.UTF8.GetBytes("q");
        public static readonly byte[] QI = Encoding.UTF8.GetBytes("qi");
        public static readonly byte[] Use = Encoding.UTF8.GetBytes("use");
        public static readonly byte[] X5c = Encoding.UTF8.GetBytes("x5c");
        public static readonly byte[] X5t = Encoding.UTF8.GetBytes("x5t");
        public static readonly byte[] X5tS256 = Encoding.UTF8.GetBytes("x5t#S256");
        public static readonly byte[] X5u = Encoding.UTF8.GetBytes("x5u");
        public static readonly byte[] X = Encoding.UTF8.GetBytes("x");
        public static readonly byte[] Y = Encoding.UTF8.GetBytes("y");
    }
#pragma warning restore 1591
}
