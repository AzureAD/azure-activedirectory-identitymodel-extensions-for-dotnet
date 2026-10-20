// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Microsoft.IdentityModel.Tokens
{
    /// <summary>
    /// Creates opaque, format-separated replay cache identities. Call only for authenticated tokens.
    /// </summary>
    internal static class TokenReplayCacheIdentity
    {
        internal static string CreateJwt(string token)
        {
            // Preserve the exact signing input, including its original base64url encoding.
            return Create("JWT", token.Substring(0, token.LastIndexOf('.')), string.Empty);
        }

        internal static string CreateSaml(string format, string issuer, string assertionId)
        {
            return Create(format, issuer, assertionId);
        }

        private static string Create(string format, string first, string second)
        {
            using (var stream = new MemoryStream())
            {
                // BinaryWriter prefixes each UTF-8 field with its byte length. Strict encoding
                // avoids mapping distinct ill-formed UTF-16 strings to replacement characters.
                using (var writer = new BinaryWriter(stream, new UTF8Encoding(false, true), true))
                {
                    writer.Write("Microsoft.IdentityModel.TokenReplayCacheIdentity.v1");
                    writer.Write(format);
                    writer.Write(first);
                    writer.Write(second);
                }

                using (var sha256 = SHA256.Create())
                    return "IM.Replay.v1." + Base64UrlEncoder.Encode(sha256.ComputeHash(stream.ToArray()));
            }
        }
    }
}
