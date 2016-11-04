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

using System;

namespace Microsoft.IdentityModel.Tokens
{
    internal static class ByteExtensions
    {
        internal static bool SequenceEqualConstantTime( this byte[] self, byte[] other )
        {
            if ( self == null )
                throw new ArgumentNullException( "self" );

            if ( other == null )
                throw new ArgumentNullException( "other" );

            // Constant time comparison of two byte arrays
            uint difference = (uint)self.Length ^ (uint)other.Length;

            for ( var i = 0; i < self.Length && i < other.Length; i++ )
            {
                difference |= (uint)( self[i] ^ other[i] );
            }

            return difference == 0;
        }

        internal static byte[] Or( this byte[] self, byte[] other )
        {
            return Or( self, other, 0 );
        }

        internal static byte[] Or( this byte[] self, byte[] other, int offset )
        {
            if ( self == null )
                throw new ArgumentNullException( "self" );

            if ( other == null )
                throw new ArgumentNullException( "other" );

            if ( self.Length > other.Length - offset )
                throw new ArgumentException( "self and other lengths do not match" );

            var result = new byte[self.Length];

            for ( var i = 0; i < self.Length; i++ )
            {
                result[i] = (byte)( self[i] | other[offset + i] );
            }

            return result;
        }

        internal static byte[] Xor( this byte[] self, byte[] other, bool inPlace = false )
        {
            return Xor( self, other, 0, inPlace );
        }

        internal static byte[] Xor( this byte[] self, byte[] other, int offset, bool inPlace = false )
        {
            if ( self == null )
                throw new ArgumentNullException( "self" );

            if ( other == null )
                throw new ArgumentNullException( "other" );

            if ( self.Length > other.Length - offset )
                throw new ArgumentException( "self and other lengths do not match" );

            if ( inPlace )
            {
                for ( var i = 0; i < self.Length; i++ )
                {
                    self[i] = (byte)( self[i] ^ other[offset + i] );
                }

                return self;
            }
            else
            {
                var result = new byte[self.Length];

                for ( var i = 0; i < self.Length; i++ )
                {
                    result[i] = (byte)( self[i] ^ other[offset + i] );
                }

                return result;
            }
        }

        internal static void Zero( this byte[] self )
        {
            if ( self == null )
                throw new ArgumentNullException( "self" );

            for ( var i = 0; i < self.Length; i++ )
            {
                self[i] = 0;
            }
        }
    }
}
