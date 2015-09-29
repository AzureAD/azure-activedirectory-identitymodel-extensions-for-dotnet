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

using System.Collections.Generic;
using System.Text;

namespace System.IdentityModel.Tokens
{
    public static class Utility
    {
        public const string Empty = "empty";
        public const string Null = "null";

        /// <summary>
        /// Serializes the list of strings into string as follows:
        /// 'str1','str2','str3' ...
        /// </summary>
        /// <param name="strings">
        /// The strings used to build a comma delimited string.
        /// </param>
        /// <returns>
        /// The single <see cref="string"/>.
        /// </returns>
        internal static string SerializeAsSingleCommaDelimitedString(IEnumerable<string> strings)
        {
            if (null == strings)
            {
                return Utility.Null;
            }

            StringBuilder sb = new StringBuilder();
            bool first = true;
            foreach (string str in strings)
            {
                if (first)
                {
                    sb.AppendFormat("{0}", str ?? Utility.Null);
                    first = false;
                }
                else
                {
                    sb.AppendFormat(", {0}", str ?? Utility.Null);
                }
            }

            if (first)
            {
                return Utility.Empty;
            }

            return sb.ToString();
        }

        public static bool IsHttps(string address)
        {
            if (string.IsNullOrEmpty(address))
            {
                return false;
            }

            try
            {
                Uri uri = new Uri(address);
                return IsHttps(new Uri(address));
            }
            catch (UriFormatException)
            {
                return false;
            }

        }

        public static bool IsHttps(Uri uri)
        {
            if (uri == null)
            {
                return false;
            }
#if DNXCORE50
            return uri.Scheme.Equals("https", StringComparison.OrdinalIgnoreCase); //Uri.UriSchemeHttps is internal in dnxcore
#else
            return uri.Scheme.Equals(Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase);
#endif
        }
    }
}