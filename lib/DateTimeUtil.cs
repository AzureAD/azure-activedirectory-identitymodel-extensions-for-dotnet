//----------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
//----------------------------------------------------------------

using System;
using System.Diagnostics;
using System.Globalization;

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
