// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Buffers;
#if NET6_0_OR_GREATER
using System.Text;
#endif
using Microsoft.IdentityModel.Logging;

namespace Microsoft.IdentityModel.Tokens
{
    /// <summary>
    /// Encodes and Decodes strings as base64url encoding.
    /// </summary>
    public static class LegacyBase64UrlEncoder
    {
        private const char Base64PadCharacter = '=';
        private const char Base64Character62 = '+';
        private const char Base64Character63 = '/';
        private const char Base64UrlCharacter62 = '-';
        private const char Base64UrlCharacter63 = '_';


        /// <summary>
        /// Populates a <see cref="Span{T}"/> with the base64url encoded representation of a <see cref="ReadOnlySpan{T}"/> of bytes.
        /// </summary>
        /// <param name="inArray">A read-only span of bytes to encode.</param>
        /// <param name="output">The span of characters to write the encoded output.</param>
        /// <returns>The number of characters written to the output span.</returns>
        public static int Encode(ReadOnlySpan<byte> inArray, Span<char> output)
        {
            int lengthmod3 = inArray.Length % 3;
            int limit = (inArray.Length - lengthmod3);
            ReadOnlySpan<byte> table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"u8;

            int i, j = 0;

            // takes 3 bytes from inArray and insert 4 bytes into output
            for (i = 0; i < limit; i += 3)
            {
                byte d0 = inArray[i];
                byte d1 = inArray[i + 1];
                byte d2 = inArray[i + 2];

                output[j + 0] = (char)table[d0 >> 2];
                output[j + 1] = (char)table[((d0 & 0x03) << 4) | (d1 >> 4)];
                output[j + 2] = (char)table[((d1 & 0x0f) << 2) | (d2 >> 6)];
                output[j + 3] = (char)table[d2 & 0x3f];
                j += 4;
            }

            //Where we left off before
            i = limit;

            switch (lengthmod3)
            {
                case 2:
                    {
                        byte d0 = inArray[i];
                        byte d1 = inArray[i + 1];

                        output[j + 0] = (char)table[d0 >> 2];
                        output[j + 1] = (char)table[((d0 & 0x03) << 4) | (d1 >> 4)];
                        output[j + 2] = (char)table[(d1 & 0x0f) << 2];
                        j += 3;
                    }
                    break;
                case 1:
                    {
                        byte d0 = inArray[i];

                        output[j + 0] = (char)table[d0 >> 2];
                        output[j + 1] = (char)table[(d0 & 0x03) << 4];
                        j += 2;
                    }
                    break;

                    //default or case 0: no further operations are needed.
            }

            return j;
        }

        /// <summary>
        /// Decodes a base64url encoded string into a byte array.
        /// </summary>
        /// <param name="strSpan">The base64url encoded string.</param>
        /// <returns>The UTF-8 byte array.</returns>
        internal static byte[] Decode(ReadOnlySpan<char> strSpan)
        {
            int mod = strSpan.Length % 4;
            if (mod == 1)
                throw LogHelper.LogExceptionMessage(new FormatException(LogHelper.FormatInvariant(LogMessages.IDX10400, strSpan.ToString())));

            bool needReplace = strSpan.IndexOfAny(Base64UrlCharacter62, Base64UrlCharacter63) >= 0;
            int decodedLength = strSpan.Length + (4 - mod) % 4;
#if NET6_0_OR_GREATER
            Span<byte> output = new byte[decodedLength];
            int length = Decode(strSpan, output, needReplace, decodedLength);
            return output.Slice(0, length).ToArray();
#else
            return UnsafeDecode(strSpan, needReplace, decodedLength);
#endif
        }

        /// <summary>
        /// Entry point for base64url decoding.
        /// </summary>
        /// <param name="strSpan">The base64url encoded string.</param>
        /// <param name="output">The preallocated buffer for the decoded bytes</param>
        /// <returns>The UTF-8 byte array.</returns>
        internal static void Decode(ReadOnlySpan<char> strSpan, Span<byte> output)
        {
            int mod = strSpan.Length % 4;
            if (mod == 1)
                throw LogHelper.LogExceptionMessage(new FormatException(LogHelper.FormatInvariant(LogMessages.IDX10400, strSpan.ToString())));
            bool needReplace = strSpan.IndexOfAny(Base64UrlCharacter62, Base64UrlCharacter63) >= 0;
            int decodedLength = strSpan.Length + (4 - mod) % 4;
#if NET6_0_OR_GREATER
            Decode(strSpan, output, needReplace, decodedLength);
#else
            Decode(strSpan, output, needReplace, decodedLength);
#endif
        }

#if NET6_0_OR_GREATER
        /// <summary>
        /// Decodes a base64url encoded string into bytes, handling padding and character replacement.
        /// </summary>
        /// <param name="strSpan">The base64url encoded string to decode.</param>
        /// <param name="output">The span to write the decoded bytes to.</param>
        /// <param name="needReplace">Indicates whether the input contains base64url-specific characters that need replacement.</param>
        /// <param name="decodedLength">The expected length of the decoded string after padding.</param>
        /// <returns>The number of bytes written to the output span.</returns>
        internal static int Decode(ReadOnlySpan<char> strSpan, Span<byte> output, bool needReplace, int decodedLength)
        {
            // If the incoming chars don't contain any of the base64url characters that need to be replaced,
            // and if the incoming chars are of the exact right length, then we'll be able to just pass the
            // incoming chars directly to DecodeFromUtf8InPlace. Otherwise, rent an array, copy all the
            // data into it, and do whatever fixups are necessary on that copy, then pass that copy into
            // DecodeFromUtf8InPlace.

            const int StackAllocThreshold = 512;
            char[] arrayPoolChars = null;
            scoped Span<char> charsSpan = default;
            scoped ReadOnlySpan<char> source = strSpan;

            if (needReplace || decodedLength != source.Length)
            {
                charsSpan = decodedLength <= StackAllocThreshold ?
                    stackalloc char[StackAllocThreshold] :
                    arrayPoolChars = ArrayPool<char>.Shared.Rent(decodedLength);
                charsSpan = charsSpan.Slice(0, decodedLength);

                source = HandlePaddingAndReplace(source, charsSpan, needReplace);
            }

            byte[] arrayPoolBytes = null;
            Span<byte> bytesSpan = decodedLength <= StackAllocThreshold ?
                stackalloc byte[StackAllocThreshold] :
                arrayPoolBytes = ArrayPool<byte>.Shared.Rent(decodedLength);

            int length = Encoding.UTF8.GetBytes(source, bytesSpan);
            Span<byte> utf8Span = bytesSpan.Slice(0, length);
            try
            {
                OperationStatus status = System.Buffers.Text.Base64.DecodeFromUtf8InPlace(utf8Span, out int bytesWritten);
                if (status != OperationStatus.Done)
                    throw LogHelper.LogExceptionMessage(new FormatException(LogHelper.FormatInvariant(LogMessages.IDX10400, strSpan.ToString())));

                utf8Span.Slice(0, bytesWritten).CopyTo(output);

                return bytesWritten;
            }
            finally
            {
                if (arrayPoolBytes is not null)
                {
                    bytesSpan.Clear();
                    ArrayPool<byte>.Shared.Return(arrayPoolBytes);
                }

                if (arrayPoolChars is not null)
                {
                    charsSpan.Clear();
                    ArrayPool<char>.Shared.Return(arrayPoolChars);
                }
            }
        }
#else
        /// <summary>
        /// Wrapper method for unsafeDecode.
        /// </summary>
        /// <param name="strSpan">The base64url encoded string to decode.</param>
        /// <param name="output">The span to write the decoded bytes to.</param>
        /// <param name="needReplace">Indicates whether the input contains base64url-specific characters that need replacement.</param>
        /// <param name="decodedLength">The expected length of the decoded string after padding.</param>
        /// <returns>The number of bytes written to the output span.</returns>
        private static void Decode(ReadOnlySpan<char> strSpan, Span<byte> output, bool needReplace, int decodedLength)
        {
            byte[] result = UnsafeDecode(strSpan, needReplace, decodedLength);
            result.CopyTo(output);

        }
#endif

        /// <summary>
        /// Prepares a base64url encoded string for standard base64 decoding by adding any missing padding
        /// characters and replacing base64url-specific characters ('-' and '_') with standard base64 
        /// characters ('+' and '/').
        /// </summary>
        /// <param name="source">The original base64url encoded string.</param>
        /// <param name="charsSpan">The destination span where the prepared string will be stored.</param>
        /// <param name="needReplace">Indicates whether the input contains base64url-specific characters that need replacement.</param>
        /// <returns>A read-only span containing the prepared string ready for standard base64 decoding.</returns>
        private static ReadOnlySpan<char> HandlePaddingAndReplace(ReadOnlySpan<char> source, Span<char> charsSpan, bool needReplace)
        {
            source.CopyTo(charsSpan);
            if (source.Length < charsSpan.Length)
            {
                charsSpan[source.Length] = Base64PadCharacter;
                if (source.Length + 1 < charsSpan.Length)
                {
                    charsSpan[source.Length + 1] = Base64PadCharacter;
                }
            }

            if (needReplace)
            {
                Span<char> remaining = charsSpan;
                int pos;
                while ((pos = remaining.IndexOfAny(Base64UrlCharacter62, Base64UrlCharacter63)) >= 0)
                {
                    remaining[pos] = (remaining[pos] == Base64UrlCharacter62) ? Base64Character62 : Base64Character63;
                    remaining = remaining.Slice(pos + 1);
                }
            }

            return charsSpan;
        }


        /// <summary>
        /// Decodes a base64url encoded string into a byte array using unsafe code for pre-.NET 6 platforms.
        /// </summary>
        /// <param name="strSpan">The base64url encoded string to decode.</param>
        /// <param name="needReplace">Indicates whether the input contains base64url-specific characters that need replacement.</param>
        /// <param name="decodedLength">The expected length of the string after padding is applied.</param>
        /// <returns>The decoded byte array.</returns>
        internal static unsafe byte[] UnsafeDecode(ReadOnlySpan<char> strSpan, bool needReplace, int decodedLength)
        {
            if (needReplace)
            {
                string decodedString = new(char.MinValue, decodedLength);
                fixed (char* dest = decodedString)
                {
                    int i = 0;
                    for (; i < strSpan.Length; i++)
                    {
                        if (strSpan[i] == Base64UrlCharacter62)
                            dest[i] = Base64Character62;
                        else if (strSpan[i] == Base64UrlCharacter63)
                            dest[i] = Base64Character63;
                        else
                            dest[i] = strSpan[i];
                    }

                    for (; i < decodedLength; i++)
                        dest[i] = Base64PadCharacter;
                }

                return Convert.FromBase64String(decodedString);
            }
            else
            {
                if (decodedLength == strSpan.Length)
                {
                    return Convert.FromBase64CharArray(strSpan.ToArray(), 0, strSpan.Length);
                }
                else
                {
                    string decodedString = new(char.MinValue, decodedLength);
                    fixed (char* src = strSpan)
                    fixed (char* dest = decodedString)
                    {
                        Buffer.MemoryCopy(src, dest, strSpan.Length * 2, strSpan.Length * 2);

                        dest[strSpan.Length] = Base64PadCharacter;
                        if (strSpan.Length + 2 == decodedLength)
                            dest[strSpan.Length + 1] = Base64PadCharacter;
                    }

                    return Convert.FromBase64String(decodedString);
                }
            }
        }
    }
}
