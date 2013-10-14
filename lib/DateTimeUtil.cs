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

using System.Diagnostics;

namespace System.IdentityModel.Tokens
{
    [DebuggerNonUserCode]
    internal static class DateTimeUtil
    {
        /// <summary>
        /// Add a DateTime and a TimeSpan.
        /// The maximum time is DateTime.MaxTime.  It is not an error if time + timespan > MaxTime.
        /// Just return MaxTime.
        /// </summary>
        /// <param name="time">Initial <see cref="DateTime"/> value.</param>
        /// <param name="timespan"><see cref="TimeSpan"/> to add.</param>
        /// <returns></returns>
        public static DateTime Add( DateTime time, TimeSpan timespan )
        {
            if ( timespan == TimeSpan.Zero )
            {
                return time;
            }

            if ( timespan > TimeSpan.Zero && DateTime.MaxValue - time <= timespan )
            {
                return GetMaxValue( time.Kind );
            }

            if ( timespan < TimeSpan.Zero && DateTime.MinValue - time >= timespan )
            {
                return GetMinValue( time.Kind );
            }

            return time + timespan;
        }

        public static DateTime GetMaxValue( DateTimeKind kind )
        {
            return new DateTime( DateTime.MaxValue.Ticks, kind );
        }

        public static DateTime GetMinValue( DateTimeKind kind )
        {
            return new DateTime( DateTime.MinValue.Ticks, kind );
        }

        /// <summary>
        /// Checks that an instant in time falls within a valid date range, accounting for clock skew.
        /// </summary>
        /// <param name="instant">Instant in time to validate against the date range.</param>
        /// <param name="startDate">Start date of the date range.</param>
        /// <param name="endDate">End date of the date range.</param>
        /// <param name="clockSkew">Clock skew tolerance.</param>
        /// <returns>true if the instant falls between the date range, false otherwise.</returns>
        public static bool IsDateTimeWithinAllowedRange( DateTime instant, DateTime startDate, DateTime endDate, TimeSpan clockSkew )
        {
            return startDate <= Add( instant, clockSkew )
                && endDate >= Add( instant, clockSkew.Negate() );
        }
    }
}
