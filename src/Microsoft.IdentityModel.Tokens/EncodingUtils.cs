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

#if !NET45

using System;
using System.Buffers;
using System.Text;

namespace Microsoft.IdentityModel.Tokens
{
    /// <summary>
    /// Collection of text encoding related helper methods.
    /// </summary>
    internal static class EncodingUtils
    {
        /// <summary>
        /// Obtains bytes from a string using the Encoding and then performs an action.
        /// </summary>
        /// <param name="input">String to process.</param>
        /// <param name="encoding">Encoding used to obtain bytes.</param>
        /// <param name="action">Operation to invoke with result which is byte array and length of useful data in array with offset as 0.</param>
        /// <typeparam name="T">Return type of operation.</typeparam>
        /// <returns>Instance of {T}.</returns>
        /// <remarks>
        /// The encoding operation uses shared memory pool to avoid allocations.
        /// The length of the rented array of bytes may be larger than the decoded bytes, therefore the action needs to know the actual length to use.
        /// <see cref="Encoding.GetBytes(string, int, int, byte[], int)"/> is passed to the action.
        /// </remarks>
        internal static T PerformEncodingDependentOperation<T>(
            string input,
            Encoding encoding,
            Func<byte[], int, T> action)
        {
            return PerformEncodingDependentOperation<T>(input, 0, input.Length, encoding, action);
        }

        /// <summary>
        /// Obtains bytes from a string using the Encoding and then performs an action.
        /// </summary>
        /// <param name="input">String to process.</param>
        /// <param name="offset">Index to start from in <paramref name="input"/>.</param>
        /// <param name="length">Length of characters to operate in <paramref name="input"/> from <paramref name="offset"/>.</param>
        /// <param name="encoding">Encoding used to obtain bytes.</param>
        /// <param name="action">Operation to invoke with result which is byte array and length of useful data in array with offset as 0.</param>
        /// <typeparam name="T">Return type of operation.</typeparam>
        /// <returns>Instance of {T}.</returns>
        /// <remarks>
        /// The encoding operation uses shared memory pool to avoid allocations.
        /// The length of the rented array of bytes may be larger than the decoded bytes, therefore the action needs to know the actual length to use.
        /// <see cref="Encoding.GetBytes(string, int, int, byte[], int)"/> is passed to the action.
        /// </remarks>
        internal static T PerformEncodingDependentOperation<T>(
            string input,
            int offset,
            int length,
            Encoding encoding,
            Func<byte[], int, T> action)
        {
            int size = encoding.GetMaxByteCount(length);
            byte[] bytes = ArrayPool<byte>.Shared.Rent(size);
            try
            {
                size = encoding.GetBytes(input, offset, length, bytes, 0);
                return action(bytes, size);
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(bytes);
            }
        }

        /// <summary>
        /// Obtains bytes from a string using the Encoding and then performs an action.
        /// </summary>
        /// <param name="input">String to process.</param>
        /// <param name="offset">Index to start from in <paramref name="input"/>.</param>
        /// <param name="length">Length of characters to operate in <paramref name="input"/> from <paramref name="offset"/>.</param>
        /// <param name="encoding">Encoding used to obtain bytes.</param>
        /// <param name="argx">Input parameter 1 to action.</param>
        /// <param name="argy">Input parameter 2 to action.</param>
        /// <param name="argz">Input parameter 3 to action.</param>
        /// <param name="action">Action to perform with bytes.</param>
        /// <typeparam name="T">Return type of operation.</typeparam>
        /// <typeparam name="TX">Type of Input parameter 1 to action.</typeparam>
        /// <typeparam name="TY">Type of Input parameter 2 to action.</typeparam>
        /// <typeparam name="TZ">Type of Input parameter 3 to action.</typeparam>
        /// <returns>Instance of {T}.</returns>
        /// <remarks>
        /// The encoding operation uses shared memory pool to avoid allocations.
        /// The length of the rented array of bytes may be larger than the decoded bytes, therefore the action needs to know the actual length to use.
        /// <see cref="Encoding.GetBytes(string, int, int, byte[], int)"/> is passed to the action.
        /// </remarks>
        internal static T PerformEncodingDependentOperation<T, TX, TY, TZ>(
            string input,
            int offset,
            int length,
            Encoding encoding,
            TX argx,
            TY argy,
            TZ argz,
            Func<byte[], int, TX, TY, TZ, T> action)
        {
            int size = encoding.GetMaxByteCount(length);
            byte[] bytes = ArrayPool<byte>.Shared.Rent(size);
            try
            {
                size = encoding.GetBytes(input, offset, length, bytes, 0);
                return action(bytes, size, argx, argy, argz);
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(bytes);
            }
        }

        /// <summary>
        /// Encodes the string using given Encoding, and invokes the operation with the result.
        /// </summary>
        /// <typeparam name="T">Return type of operation.</typeparam>
        /// <typeparam name="TX">Input parameter to operation.</typeparam>
        /// <param name="input">String to process.</param>
        /// <param name="encoding">Encoding used to obtain bytes.</param>
        /// <param name="parameter">Additional operation parameter.</param>
        /// <param name="action">Operation to invoke with result which is byte array and length of useful data in array with offset as 0.</param>
        /// <returns>Result of operation.</returns>
        /// <remarks>
        /// The encoding operation uses shared memory pool to avoid allocations.
        /// The length of the rented array of bytes may be larger than the decoded bytes, therefore the action needs to know the actual length to use.
        /// <see cref="Encoding.GetBytes(string, int, int, byte[], int)"/> is passed to the action.
        /// </remarks>
        internal static T PerformEncodingDependentOperation<T, TX>(
            string input,
            Encoding encoding,
            TX parameter,
            Func<byte[], int, TX, T> action)
        {
            return PerformEncodingDependentOperation(input, 0, input.Length, encoding, parameter, action);
        }

        /// <summary>
        /// Obtains bytes from a string using the Encoding and then performs an action.
        /// </summary>
        /// <param name="input">String to process.</param>
        /// <param name="offset">Index to start from in <paramref name="input"/>.</param>
        /// <param name="length">Length of characters to operate in <paramref name="input"/> from <paramref name="offset"/>.</param>
        /// <param name="encoding">Encoding used to obtain bytes.</param>
        /// <param name="parameter">Additional operation parameter.</param>
        /// <param name="action">Operation to invoke with result which is byte array and length of useful data in array with offset as 0.</param>
        /// <typeparam name="T">Return type of operation.</typeparam>
        /// <typeparam name="TX">Input parameter to operation.</typeparam>
        /// <returns>Instance of {T}.</returns>
        /// <remarks>
        /// The encoding operation uses shared memory pool to avoid allocations.
        /// The length of the rented array of bytes may be larger than the decoded bytes, therefore the action needs to know the actual length to use.
        /// <see cref="Encoding.GetBytes(string, int, int, byte[], int)"/> is passed to the action.
        /// </remarks>
        internal static T PerformEncodingDependentOperation<T, TX>(
            string input,
            int offset,
            int length,
            Encoding encoding,
            TX parameter,
            Func<byte[], int, TX, T> action)
        {
            
            int size = encoding.GetMaxByteCount(length);
            byte[] bytes = ArrayPool<byte>.Shared.Rent(size);
            try
            {
                size = encoding.GetBytes(input, offset, length, bytes, 0);
                return action(bytes, size, parameter);
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(bytes);
            }
        }
    }
}
#endif
