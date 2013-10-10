//------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
//------------------------------------------------------------

namespace System.IdentityModel.Tokens
{
    /// <summary>
    /// Returns the absolute DateTime or the Seconds since Unix Epoch, where Epoch is UTC 1970-01-01T0:0:0Z.
    /// </summary>
    internal class EpochTime
    {
        public static readonly DateTime UnixEpoch = new DateTime( 1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc );
       
        /// <summary>
        /// Per JWT spec:
        /// Gets the number of seconds from 1970-01-01T0:0:0Z as measured in UTC until the desired date/time.
        /// </summary>
        /// <remarks>if dateTimeUtc less than UnixEpoch, return 0</remarks>
        public static Int64 GetIntDate( DateTime datetime )
        {
            DateTime dateTimeUtc = datetime;
            if ( datetime.Kind != DateTimeKind.Utc )
            {
                dateTimeUtc = datetime.ToUniversalTime();
            }

            if ( dateTimeUtc.ToUniversalTime() <= UnixEpoch )
            {
                return 0;
            }

            return (Int64)( dateTimeUtc - UnixEpoch ).TotalSeconds;
        }

        public static DateTime DateTime( Int64 secondsSinceUnixEpoch )
        {
            if ( secondsSinceUnixEpoch <= 0 )
            {
                return UnixEpoch;
            }

            return DateTimeUtil.Add( UnixEpoch, TimeSpan.FromSeconds( secondsSinceUnixEpoch ) ).ToUniversalTime();
        }
    }
}
