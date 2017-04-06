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
using System.Security.Cryptography;
using Microsoft.IdentityModel.Logging;

namespace Microsoft.IdentityModel.Xml
{
    internal static class CryptoHelper
    {
        private static RandomNumberGenerator _random;

        /// <summary>
        /// Provides an integer-domain mathematical operation for 
        /// Ceiling( dividend / divisor ). 
        /// </summary>
        /// <param name="dividend"></param>
        /// <param name="divisor"></param>
        /// <returns></returns>
        public static int CeilingDivide(int dividend, int divisor)
        {
            int remainder, quotient;

            remainder = dividend % divisor;
            quotient = dividend / divisor;

            if (remainder > 0)
                quotient++;

            return quotient;
        }

        public static RandomNumberGenerator RandomNumberGenerator
        {
            get
            {
                if (_random == null)
                    _random = new RNGCryptoServiceProvider();

                return _random;
            }
        }


        /// <summary>
        /// This method generates a random byte array used as entropy with the given size. 
        /// </summary>
        /// <param name="sizeInBits"></param>
        /// <returns></returns>
        public static byte[] GenerateRandomBytes(int sizeInBits)
        {
            int sizeInBytes = sizeInBits / 8;
            if (sizeInBits <= 0)
                throw LogHelper.LogExceptionMessage(new ArgumentOutOfRangeException(nameof(sizeInBits)));
            else if (sizeInBytes * 8 != sizeInBits)
                throw LogHelper.LogExceptionMessage(new ArgumentException(nameof(sizeInBits)));

            byte[] data = new byte[sizeInBytes];
            RandomNumberGenerator.GetNonZeroBytes(data);
            return data;
        }
    }
}



