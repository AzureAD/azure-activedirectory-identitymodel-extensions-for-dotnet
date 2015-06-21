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

using System;

namespace Microsoft.IdentityModel.Tokens
{
    /// <summary>
    /// Returns the absolute DateTime or the Seconds since Unix Epoch, where Epoch is UTC 1970-01-01T0:0:0Z.
    /// </summary>
    public static class EpochTime
    {
        /// <summary>
        /// DateTime as UTV for UnixEpoch
        /// </summary>
        public static readonly DateTime UnixEpoch = new DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc);

        /// <summary>
        /// Per JWT spec:
        /// Gets the number of seconds from 1970-01-01T0:0:0Z as measured in UTC until the desired date/time.
        /// </summary>
        /// <param name="datetime">The DateTime to convert to seconds.</param>
        /// <remarks>if dateTimeUtc less than UnixEpoch, return 0</remarks>
        /// <returns>the number of seconds since Unix Epoch.</returns>
        public static long GetIntDate(DateTime datetime)
        {
            DateTime dateTimeUtc = datetime;
            if (datetime.Kind != DateTimeKind.Utc)
            {
                dateTimeUtc = datetime.ToUniversalTime();
            }

            if (dateTimeUtc.ToUniversalTime() <= UnixEpoch)
            {
                return 0;
            }

            return (long)(dateTimeUtc - UnixEpoch).TotalSeconds;
        }

        /// <summary>
        /// Creates a DateTime from epoch time.
        /// </summary>
        /// <param name="secondsSinceUnixEpoch">Number of seconds.</param>
        /// <returns>The DateTime in UTC.</returns>
        public static DateTime DateTime(long secondsSinceUnixEpoch)
        {
            if (secondsSinceUnixEpoch <= 0)
            {
                return UnixEpoch;
            }

            return DateTimeUtil.Add(UnixEpoch, TimeSpan.FromSeconds(secondsSinceUnixEpoch)).ToUniversalTime();
        }
    }
}
