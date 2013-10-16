// ----------------------------------------------------------------------------------
//
// Copyright Microsoft Corporation
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
// ----------------------------------------------------------------------------------

namespace System.IdentityModel
{
    using System.Collections.Generic;
    using System.Text;

    internal static class Utility
    {
        /// <summary>
        /// Serializes the list of strings into string as follows:
        /// 'str1','str2','str3'
        /// </summary>
        internal static string SerializeAsSingleCommaDelimitedString(IEnumerable<string> strings)
        {
            if (null == strings)
            {
                return TextStrings.Null;
            }

            StringBuilder sb = new StringBuilder();
            bool first = true;
            foreach (string str in strings)
            {
                if (first)
                {
                    sb.AppendFormat("{0}", str ?? TextStrings.Null);
                    first = false;
                }
                else
                {
                    sb.AppendFormat(", {0}", str ?? TextStrings.Null);
                }
            }

            if (first)
            {
                return TextStrings.Empty;
            }

            return sb.ToString();
        }
    }
}