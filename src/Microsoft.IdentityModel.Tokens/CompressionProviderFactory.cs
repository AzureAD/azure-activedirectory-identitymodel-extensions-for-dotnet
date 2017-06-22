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
using System.IO;
using System.IO.Compression;
using System.Text;
using Microsoft.IdentityModel.Logging;

namespace Microsoft.IdentityModel.Tokens
{
    /// <summary>
    /// Compression provider factory for compression and decompression.
    /// </summary>
    public class CompressionProviderFactory
    {
        private static CompressionProviderFactory _default;

        /// <summary>
        /// Returns the default <see cref="CompressionProviderFactory"/> instance.
        /// </summary>
        public static CompressionProviderFactory Default
        {
            get { return _default; }
            set
            {
                if (value == null)
                    throw LogHelper.LogArgumentNullException("value");

                _default = value;
            }
        }

        /// <summary>
        /// Extensibility point for custom compression support application wide.
        /// </summary>
        public ICompressionProvider CustomCompressionProvider { get; set; }

        /// <summary>
        /// Static constructor that initializes the default <see cref="CompressionProviderFactory"/>.
        /// </summary>
        static CompressionProviderFactory()
        {
            Default = new CompressionProviderFactory();
        }

        /// <summary>
        /// Default constructor for <see cref="CompressionProviderFactory"/>.
        /// </summary>
        public CompressionProviderFactory()
        {
        }

        /// <summary>
        /// Constructor that creates a deep copy of given <see cref="CompressionProviderFactory"/> object.
        /// </summary>
        /// <param name="other"><see cref="CompressionProviderFactory"/> to copy from.</param>
        public CompressionProviderFactory(CompressionProviderFactory other)
        {
            if (other == null)
                throw LogHelper.LogArgumentNullException(nameof(other));

            CustomCompressionProvider = other.CustomCompressionProvider;
        }

        /// <summary>
        /// Answers if an algorithm is supported
        /// </summary>
        /// <param name="algorithm">the name of the crypto algorithm</param>
        /// <returns></returns>
        public virtual bool IsSupportedAlgorithm(string algorithm)
        {
            if (CustomCompressionProvider != null && CustomCompressionProvider.IsSupportedAlgorithm(algorithm))
                return true;

            return IsSupportedCompressionAlgorithm(algorithm);
        }

        private bool IsSupportedCompressionAlgorithm(string algorithm)
        {
            switch (algorithm)
            {
                case CompressionAlgorithm.Deflate:
                    return true;

                default:
                    return false;
            }
        }

        /// <summary>
        /// Decompress the value using the given algorithm
        /// </summary>
        /// <param name="algorithm">Decompression algorithm</param>
        /// <param name="value">The value to decompress</param>
        /// <returns></returns>
        public string Decompress(string algorithm, byte[] value)
        {
            if (algorithm == null)
                throw LogHelper.LogArgumentNullException(algorithm);

            if (value == null)
                return null;

            if (CustomCompressionProvider != null && CustomCompressionProvider.IsSupportedAlgorithm(algorithm))
            {
                var decompressed = CustomCompressionProvider.Decompress(algorithm, value);
                if (decompressed == null)
                    throw LogHelper.LogExceptionMessage(new InvalidOperationException(LogHelper.FormatInvariant(LogMessages.IDX10673, algorithm)));
                return decompressed;
            }

            if (IsSupportedAlgorithm(algorithm))
                return DecompressUtil(algorithm, value);

            throw LogHelper.LogExceptionMessage(new NotSupportedException(LogHelper.FormatInvariant(LogMessages.IDX10652, algorithm)));
        }

        private string DecompressUtil(string algorithm, byte[] value)
        {
            if (algorithm.Equals(CompressionAlgorithm.Deflate))
                return CompressionUtils.DecompressWithDeflate(value);

            return null;
        }

        // TODO
        ///// <summary>
        ///// Compress the value using the given algorithm
        ///// </summary>
        ///// <param name="algorithm">Compression algorithm</param>
        ///// <param name="value">The value to compress</param>
        ///// <returns></returns>
        //public byte[] Compress(string algorithm, string value)
        //{
        //    if (algorithm == null)
        //        throw LogHelper.LogArgumentNullException(algorithm);

        //    if (string.IsNullOrEmpty(value))
        //        return null;

        //    if (CustomCompressionProvider != null && CustomCompressionProvider.IsSupportedAlgorithm(algorithm))
        //    {
        //        var compressed = CustomCompressionProvider.Compress(algorithm, value);
        //        if (compressed == null)
        //            throw LogHelper.LogExceptionMessage(new InvalidOperationException(LogHelper.FormatInvariant(LogMessages.IDX10674, algorithm)));
        //        return compressed;
        //    }

        //    if (IsSupportedAlgorithm(algorithm))
        //        return CompressUtil(algorithm, value);

        //    throw LogHelper.LogExceptionMessage(new NotSupportedException(LogHelper.FormatInvariant(LogMessages.IDX10652, algorithm)));
        //}

        //private byte[] CompressUtil(string algorithm, string value)
        //{
        //    if (algorithm.Equals(CompressionAlgorithm.Deflate))
        //        return CompressionUtils.CompressWithDeflate(value);

        //    return null;
        //}
    }

    /// <summary>
    /// Compression algorithms.
    /// </summary>
    public class CompressionAlgorithm
    {
#pragma warning disable 1591
        public const string Deflate = "DEF";
#pragma warning restore 1591
    }

    /// <summary>
    /// Utility function for compression and decompression.
    /// </summary>
    public class CompressionUtils
    {
        /// <summary>
        /// Compress the value using DEFLATE algorithm.
        /// </summary>
        /// <param name="value">The string to compress</param>
        /// <returns>Compression bytes</returns>
        public static byte[] CompressWithDeflate(string value)
        {
            using (MemoryStream output = new MemoryStream())
            {
                using (DeflateStream deflateStream = new DeflateStream(output, CompressionMode.Compress))
                {
                    using (StreamWriter writer = new StreamWriter(deflateStream, Encoding.UTF8))
                    {
                        writer.Write(value);
                    }
                }

                return output.ToArray();
            }
        }

        /// <summary>
        /// Decompress the value using DEFLATE algorithm.
        /// </summary>
        /// <param name="value">The bytes to decompress</param>
        /// <returns>Decompression string</returns>
        public static string DecompressWithDeflate(byte[] value)
        {
            using (MemoryStream inputStream = new MemoryStream(value))
            {
                using (DeflateStream deflateStream = new DeflateStream(inputStream, CompressionMode.Decompress))
                {
                    using (StreamReader reader = new StreamReader(deflateStream, Encoding.UTF8))
                    {
                        return reader.ReadToEnd();
                    }
                }
            }
        }
    }
}

