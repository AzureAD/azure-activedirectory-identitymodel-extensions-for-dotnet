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
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;

namespace Microsoft.IdentityModel.Protocols
{
    /// <summary>
    /// Converts an object to and from a Base64Url encoded string.
    /// </summary>
    public class Base64UrlConverter : JsonConverter
    {
        
        /// <summary>
        /// Converts a byte array to a Base64Url encoded string.
        /// </summary>
        /// <param name="input">The byte array to convert</param>
        /// <returns>The Base64Url encoded form of the input</returns>
        private static string ToBase64UrlString(byte[] input)
        {
            if (input == null)
                throw LogHelper.LogArgumentNullException("input");

            return Convert.ToBase64String( input ).TrimEnd( '=' ).Replace( '+', '-' ).Replace( '/', '_' );
        }

        /// <summary>
        /// Converts a Base64Url encoded string to a byte array
        /// </summary>
        /// <param name="input">The Base64Url encoded string</param>
        /// <returns>The byte array represented by the enconded string</returns>
        private static byte[] FromBase64UrlString(string input)
        {
            if (string.IsNullOrEmpty(input))
                throw LogHelper.LogArgumentNullException("input");

            return Convert.FromBase64String( Pad( input.Replace( '-', '+' ).Replace( '_', '/' ) ) );
        }

        /// <summary>
        /// Adds padding to the input
        /// </summary>
        /// <param name="input">The input string.</param>
        /// <returns>The padded string.</returns>
        private static string Pad( string input )
        {
            var count = 3 - ( ( input.Length + 3 ) % 4 );

            if ( count == 0 )
            {
                return input;
            }

            return input + new string( '=', count );
        }

        /// <summary>
        /// Determines whether the input object type can convert to the specified object type.
        /// </summary>
        /// <param name="objectType">Type of the object.</param>
        /// <returns>true if this instance can convert the specified object type; otherwise, false.</returns>
        public override bool CanConvert( Type objectType )
        {
            if ( objectType == typeof( byte[] ) )
                return true;

            return false;
        }

        /// <summary>
        /// Reads the JSON representation of the object.
        /// </summary>
        /// <param name="reader">The <see cref="JsonReader"/> to read from.</param>
        /// <param name="objectType">Type of the object.</param>
        /// <param name="existingValue">The existing value of object being read.</param>
        /// <param name="serializer">The calling serializer <see cref="JsonSerializer"/>.</param>
        /// <returns>The object value.</returns>
        public override object ReadJson( JsonReader reader, Type objectType, object existingValue, JsonSerializer serializer )
        {
            if ( objectType != typeof( byte[] ) )
            {
                return serializer.Deserialize( reader, objectType );
            }
            else
            {
                var value = serializer.Deserialize<string>( reader );

                if ( !string.IsNullOrEmpty( value ) )
                {
                    return FromBase64UrlString( value );
                }
            }

            return null;
        }

        /// <summary>
        /// Writes the JSON representation of the object.
        /// </summary>
        /// <param name="writer">The <see cref="JsonWriter"/> to write to.</param>
        /// <param name="value">The input value.</param>
        /// <param name="serializer">The calling serializer <see cref="JsonSerializer"/>.</param>
        public override void WriteJson( JsonWriter writer, object value, JsonSerializer serializer )
        {
            if ( value.GetType() != typeof( byte[] ) )
            {
                JToken.FromObject( value ).WriteTo( writer ); 
            }
            else
            {
                JToken.FromObject( ToBase64UrlString( ( byte[] )value ) ).WriteTo( writer );
            }
        }
    }
}
