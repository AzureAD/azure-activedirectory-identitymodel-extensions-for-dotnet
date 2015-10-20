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

namespace Microsoft.IdentityModel.Protocols.OpenIdConnect
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
