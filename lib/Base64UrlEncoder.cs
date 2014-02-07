//-----------------------------------------------------------------------
// <copyright file="Base64UrlEncoder.cs" company="Microsoft">Copyright 2012 Microsoft Corporation</copyright>
// <license>
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
// </license>

namespace System.IdentityModel.Tokens
{
    using System.Diagnostics.CodeAnalysis;
    using System.Globalization;
    using System.Text;

    [SuppressMessage("StyleCop.CSharp.DocumentationRules", "SA1600:ElementsMustBeDocumented", Justification = "Suppressed for private or internal fields.")]
    internal static class Base64UrlEncoder
    {
        private static char base64PadCharacter = '=';
        private static string doubleBase64PadCharacter = string.Format(CultureInfo.InvariantCulture, "{0}{0}", base64PadCharacter);
        private static char base64Character62 = '+';
        private static char base64Character63 = '/';
        private static char base64UrlCharacter62 = '-';
        private static char _base64UrlCharacter63 = '_';

        /// <summary>
        /// The following functions perform base64url encoding which differs from regular base64 encoding as follows
        /// * padding is skipped so the pad character '=' doesn't have to be percent encoded
        /// * the 62nd and 63rd regular base64 encoding characters ('+' and '/') are replace with ('-' and '_')
        /// The changes make the encoding alphabet file and URL safe.
        /// </summary>
        /// <param name="arg">string to encode.</param>
        /// <returns>Base64Url encoding of the UTF8 bytes.</returns>
        public static string Encode(string arg)
        {
            if (null == arg)
            {
                throw new ArgumentNullException(arg);
            }

            return Encode(Encoding.UTF8.GetBytes(arg));
        }

        /// <summary>
        /// See above.
        /// </summary>
        /// <param name="arg">bytes to encode.</param>
        /// <returns>Base64Url encoding of the bytes.</returns>
        public static string Encode(byte[] arg)
        {
            if (null == arg)
            {
                throw new ArgumentNullException("arg");
            }

            string s = Convert.ToBase64String(arg);
            s = s.Split(base64PadCharacter)[0]; // Remove any trailing padding
            s = s.Replace(base64Character62, base64UrlCharacter62);  // 62nd char of encoding
            s = s.Replace(base64Character63, _base64UrlCharacter63);  // 63rd char of encoding

            return s;
        }

        /// <summary>
        /// Returns the decoded bytes.
        /// </summary>
        /// <param name="str">base64Url encoded string.</param>
        /// <returns>UTF8 bytes.</returns>
        public static byte[] DecodeBytes(string str)
        {
            if (null == str)
            {
                throw new ArgumentNullException("str");
            }

            // 62nd char of encoding
            str = str.Replace(base64UrlCharacter62, base64Character62);
            
            // 63rd char of encoding
            str = str.Replace(_base64UrlCharacter63, base64Character63);

            // check for padding
            switch (str.Length % 4)
            {
                case 0:
                    // No pad chars in this case
                    break;
                case 2:
                    // Two pad chars
                    str += doubleBase64PadCharacter;
                    break;
                case 3:
                    // One pad char
                    str += base64PadCharacter;
                    break;
                default:
                    throw new SecurityTokenException(string.Format(CultureInfo.InvariantCulture, JwtErrors.Jwt10114, str));
            }

            return Convert.FromBase64String(str);
        }

        /// <summary>
        /// Decodes the string from Base64UrlEncoded to UTF8.
        /// </summary>
        /// <param name="arg">string to decode.</param>
        /// <returns>UTF8 string.</returns>
        public static string Decode(string arg)
        {
            return Encoding.UTF8.GetString(DecodeBytes(arg));
        }
    }
}