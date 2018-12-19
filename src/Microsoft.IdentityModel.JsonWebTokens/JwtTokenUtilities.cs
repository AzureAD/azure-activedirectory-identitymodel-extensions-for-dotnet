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

using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using TokenLogMessages = Microsoft.IdentityModel.Tokens.LogMessages;

namespace Microsoft.IdentityModel.JsonWebTokens
{
    /// <summary>
    /// A class which contains useful methods for processing JWT tokens.
    /// </summary>
    public class JwtTokenUtilities
    {
        /// <summary>
        /// Regex that is used to figure out if a token is in JWS format.
        /// </summary>
        public static Regex RegexJws = new Regex(JwtConstants.JsonCompactSerializationRegex, RegexOptions.Compiled | RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(100));
        
        /// <summary>
        /// Regex that is used to figure out if a token is in JWE format.
        /// </summary>
        public static Regex RegexJwe = new Regex(JwtConstants.JweCompactSerializationRegex, RegexOptions.Compiled | RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(100));

        /// <summary>
        /// Produces a signature over the 'input'.
        /// </summary>
        /// <param name="input">String to be signed</param>
        /// <param name="signingCredentials">The <see cref="SigningCredentials"/> that contain crypto specs used to sign the token.</param>
        /// <returns>The bse64urlendcoded signature over the bytes obtained from UTF8Encoding.GetBytes( 'input' ).</returns>
        /// <exception cref="ArgumentNullException">'input' or 'signingCredentials' is null.</exception>
        public static string CreateEncodedSignature(string input, SigningCredentials signingCredentials)
        {
            if (input == null)
                throw LogHelper.LogArgumentNullException(nameof(input));

            if (signingCredentials == null)
                throw LogHelper.LogArgumentNullException(nameof(signingCredentials));

            var cryptoProviderFactory = signingCredentials.CryptoProviderFactory ?? signingCredentials.Key.CryptoProviderFactory;
            var signatureProvider = cryptoProviderFactory.CreateForSigning(signingCredentials.Key, signingCredentials.Algorithm);
            if (signatureProvider == null)
                throw LogHelper.LogExceptionMessage(new InvalidOperationException(LogHelper.FormatInvariant(TokenLogMessages.IDX10636, (signingCredentials.Key == null ? "Null" : signingCredentials.Key.ToString()), (signingCredentials.Algorithm ?? "Null"))));

            try
            {
                LogHelper.LogVerbose(LogMessages.IDX14200);
                return Base64UrlEncoder.Encode(signatureProvider.Sign(Encoding.UTF8.GetBytes(input)));
            }
            finally
            {
                cryptoProviderFactory.ReleaseSignatureProvider(signatureProvider);
            }
        }

        /// <summary>
        /// Has extra code for X509SecurityKey keys where the kid or x5t match in a case insensitive manner.
        /// </summary>
        /// <param name="kid"></param>
        /// <param name="x5t"></param>
        /// <param name="securityKey"></param>
        /// <param name="keys"></param>
        /// <returns>a key if found, null otherwise.</returns>
        internal static SecurityKey FindKeyMatch(string kid, string x5t, SecurityKey securityKey, IEnumerable<SecurityKey> keys)
        {
            // the code could be in a routine, but I chose to have duplicate code instead for performance
            if (keys == null && securityKey == null)
                return null;

            if (securityKey is X509SecurityKey x509SecurityKey1)
            {
                if (string.Equals(x5t, x509SecurityKey1.X5t, StringComparison.OrdinalIgnoreCase)
                ||  string.Equals(x5t, x509SecurityKey1.KeyId, StringComparison.OrdinalIgnoreCase)
                ||  string.Equals(kid, x509SecurityKey1.X5t, StringComparison.OrdinalIgnoreCase)
                ||  string.Equals(kid, x509SecurityKey1.KeyId, StringComparison.OrdinalIgnoreCase))
                    return securityKey;
            }
            else if (string.Equals(securityKey?.KeyId, kid, StringComparison.Ordinal))
            {
                return securityKey;
            }

            if (keys != null)
            {
                foreach (var key in keys)
                {
                    if (key is X509SecurityKey x509SecurityKey2)
                    {
                        if (string.Equals(x5t, x509SecurityKey2.X5t, StringComparison.OrdinalIgnoreCase)
                        ||  string.Equals(x5t, x509SecurityKey2.KeyId, StringComparison.OrdinalIgnoreCase)
                        ||  string.Equals(kid, x509SecurityKey2.X5t, StringComparison.OrdinalIgnoreCase)
                        ||  string.Equals(kid, x509SecurityKey2.KeyId, StringComparison.OrdinalIgnoreCase))
                            return key;
                    }
                    else if (string.Equals(key?.KeyId, kid, StringComparison.Ordinal))
                    {
                        return key;
                    }
                }
            }

            return null;
        }

        /// <summary>
        /// Generates key bytes.
        /// </summary>
        public static byte[] GenerateKeyBytes(int sizeInBits)
        {
            byte[] key = null;
            if (sizeInBits != 256 && sizeInBits != 384 && sizeInBits != 512)
                throw LogHelper.LogExceptionMessage(new ArgumentException(TokenLogMessages.IDX10401, nameof(sizeInBits)));

            var aes = Aes.Create();
            int halfSizeInBytes = sizeInBits >> 4;
            key = new byte[halfSizeInBytes << 1];
            aes.KeySize = sizeInBits >> 1;
            // The design of AuthenticatedEncryption needs two keys of the same size - generate them, each half size of what's required
            aes.GenerateKey();
            Array.Copy(aes.Key, key, halfSizeInBytes);
            aes.GenerateKey();
            Array.Copy(aes.Key, 0, key, halfSizeInBytes, halfSizeInBytes);

            return key;
        }

        /// <summary>
        /// Gets all decryption keys.
        /// </summary>
        public static IEnumerable<SecurityKey> GetAllDecryptionKeys(TokenValidationParameters validationParameters)
        {
            var decryptionKeys = new Collection<SecurityKey>();
            if (validationParameters.TokenDecryptionKey != null)
                decryptionKeys.Add(validationParameters.TokenDecryptionKey);

            if (validationParameters.TokenDecryptionKeys != null)
                foreach (SecurityKey key in validationParameters.TokenDecryptionKeys)
                    decryptionKeys.Add(key);

            return decryptionKeys;

        }
        /// <summary>
        /// Gets the DateTime using the number of seconds from 1970-01-01T0:0:0Z (UTC)
        /// </summary>
        /// <param name="key">Claim in the payload that should map to an integer, float, or string.</param>
        /// <param name="payload">The payload that contains the desired claim value.</param>
        /// <remarks>If the claim is not found, the function returns: DateTime.MinValue
        /// </remarks>
        /// <exception cref="FormatException">If the value of the claim cannot be parsed into a long.</exception>
        /// <returns>The DateTime representation of a claim.</returns>
        internal static DateTime GetDateTime(string key, JObject payload)
        {
            if (!payload.TryGetValue(key, out var jToken))
                return DateTime.MinValue;

            return EpochTime.DateTime(Convert.ToInt64(Math.Truncate(Convert.ToDouble(ParseTimeValue(jToken, key), CultureInfo.InvariantCulture))));
        }

        private static long ParseTimeValue(JToken jToken, string claimName)
        {
            if (jToken.Type == JTokenType.Integer || jToken.Type == JTokenType.Float)
            {
                return (long)jToken;
            }
            else if (jToken.Type == JTokenType.String)
            {
                if (long.TryParse((string)jToken, out long resultLong))
                    return resultLong;

                if (float.TryParse((string)jToken, out float resultFloat))
                    return (long)resultFloat;

                if (double.TryParse((string)jToken, out double resultDouble))
                    return (long)resultDouble;
            }

            throw LogHelper.LogExceptionMessage(new FormatException(LogHelper.FormatInvariant(LogMessages.IDX14300, claimName, jToken.ToString(), typeof(long))));
        }
    }
}
