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
using System.Text;

namespace Microsoft.IdentityModel.Xml
{
    abstract class CanonicalFormWriter
    {
        internal static readonly UTF8Encoding Utf8WithoutPreamble = new UTF8Encoding(false);

        protected static void Base64EncodeAndWrite(Stream stream, byte[] workBuffer, char[] base64WorkBuffer, byte[] data)
        {
            if ((data.Length / 3) * 4 + 4 > base64WorkBuffer.Length)
            {
                EncodeAndWrite(stream, Convert.ToBase64String(data));
                return;
            }

            int encodedLength = Convert.ToBase64CharArray(data, 0, data.Length, base64WorkBuffer, 0, Base64FormattingOptions.None);
            EncodeAndWrite(stream, workBuffer, base64WorkBuffer, encodedLength);
        }

        protected static void EncodeAndWrite(Stream stream, byte[] workBuffer, string s)
        {
            if (s.Length > workBuffer.Length)
            {
                EncodeAndWrite(stream, s);
                return;
            }

            for (int i = 0; i < s.Length; i++)
            {
                char c = s[i];
                if (c < 127)
                {
                    workBuffer[i] = (byte)c;
                }
                else
                {
                    EncodeAndWrite(stream, s);
                    return;
                }
            }

            stream.Write(workBuffer, 0, s.Length);
        }

        protected static void EncodeAndWrite(Stream stream, byte[] workBuffer, char[] chars)
        {
            EncodeAndWrite(stream, workBuffer, chars, chars.Length);
        }

        protected static void EncodeAndWrite(Stream stream, byte[] workBuffer, char[] chars, int count)
        {
            if (count > workBuffer.Length)
            {
                EncodeAndWrite(stream, chars, count);
                return;
            }

            for (int i = 0; i < count; i++)
            {
                char c = chars[i];
                if (c < 127)
                {
                    workBuffer[i] = (byte)c;
                }
                else
                {
                    EncodeAndWrite(stream, chars, count);
                    return;
                }
            }

            stream.Write(workBuffer, 0, count);
        }

        static void EncodeAndWrite(Stream stream, string s)
        {
            byte[] buffer = Utf8WithoutPreamble.GetBytes(s);
            stream.Write(buffer, 0, buffer.Length);
        }

        static void EncodeAndWrite(Stream stream, char[] chars, int count)
        {
            byte[] buffer = Utf8WithoutPreamble.GetBytes(chars, 0, count);
            stream.Write(buffer, 0, buffer.Length);
        }
    }
}
