//------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
//------------------------------------------------------------

using System.Collections.Generic;
using System.Globalization;
using System.Text;

namespace System.IdentityModel
{
    internal static class Utility
    {
        public static void VerifyNonNullArgument( string name, object value )
        {
            if ( null == value )
            {
                throw new ArgumentNullException( name );
            }
        }

        public static void VerifyNonNullOrEmptyStringArgument( string name, string value )
        {
            if ( null == value )
            {
                throw new ArgumentNullException( name );
            }

            if ( string.IsNullOrEmpty( value ) )
            {
                throw new ArgumentException( string.Format( CultureInfo.InvariantCulture, WifExtensionsErrors.WIF10000, name ) );
            }
        }

        public static void VerifyNonNullOrWhitespaceStringArgument( string name, string value )
        {
            if ( null == value )
            {
                throw new ArgumentNullException( name );
            }

            if ( string.IsNullOrWhiteSpace( value ) )
            {
                throw new ArgumentException( string.Format( CultureInfo.InvariantCulture, WifExtensionsErrors.WIF10002, name ) );
            }
        }

        public static void VerifyNonNullProperty( string name, object value )
        {
            if ( null == value )
            {
                throw new ArgumentException( string.Format( CultureInfo.InvariantCulture, WifExtensionsErrors.WIF10001, name ) );
            }
        }

        /// <summary>
        /// Serializes the list of strings into string as follows:
        /// 'str1','str2','str3'
        /// </summary>
        internal static string SerializeAsSingleCommaDelimitedString( IEnumerable<string> strings )
        {
            if ( null == strings )
            {
                return TextStrings.Null;
            }

            StringBuilder sb = new StringBuilder();
            bool first = true;
            foreach ( string str in strings )
            {

                if ( first )
                {
                    sb.AppendFormat( "{0}", str ?? TextStrings.Null );
                    first = false;
                }
                else
                {
                    sb.AppendFormat( ", {0}", str ?? TextStrings.Null );
                }
            }

            if ( first )
            {
                return TextStrings.Empty;
            }

            return sb.ToString();
        }
    }
}