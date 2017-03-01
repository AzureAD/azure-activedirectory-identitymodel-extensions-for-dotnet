//------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
//------------------------------------------------------------

using System;
using System.Security.Cryptography.X509Certificates;
using System.Xml;
using Microsoft.IdentityModel.Logging;

namespace Microsoft.IdentityModel.Tokens.Saml
{
    static class SecurityUtils
    {
        static DateTime _minUtcDateTime = new DateTime(DateTime.MinValue.Ticks + TimeSpan.TicksPerDay, DateTimeKind.Utc);
        static DateTime _maxUtcDateTime = new DateTime(DateTime.MaxValue.Ticks - TimeSpan.TicksPerDay, DateTimeKind.Utc);

        public static DateTime MaxUtcDateTime
        {
            get { return _maxUtcDateTime; }
        }

        public static DateTime MinUtcDateTime
        {
            get { return _minUtcDateTime; }
        }

        internal static bool IsCurrentlyTimeEffective(DateTime effectiveTime, DateTime expirationTime, TimeSpan maxClockSkew)
        {
            DateTime curEffectiveTime = (effectiveTime < DateTime.MinValue.Add(maxClockSkew)) ? effectiveTime : effectiveTime.Subtract(maxClockSkew);
            DateTime curExpirationTime = (expirationTime > DateTime.MaxValue.Subtract(maxClockSkew)) ? expirationTime : expirationTime.Add(maxClockSkew);
            DateTime curTime = DateTime.UtcNow;

            return (curEffectiveTime.ToUniversalTime() <= curTime) && (curTime < curExpirationTime.ToUniversalTime());
        }

        internal static byte[] ReadContentAsBase64(XmlDictionaryReader reader, long maxBufferSize)
        {
            if (reader == null)
                throw LogHelper.LogArgumentNullException(nameof(reader));

            // Code cloned from System.Xml.XmlDictionaryReder.
            byte[][] buffers = new byte[32][];
            byte[] buffer;
            // Its best to read in buffers that are a multiple of 3 so we don't break base64 boundaries when converting text
            int count = 384;
            int bufferCount = 0;
            int totalRead = 0;
            while (true)
            {
                buffer = new byte[count];
                buffers[bufferCount++] = buffer;
                int read = 0;
                while (read < buffer.Length)
                {
                    int actual = reader.ReadContentAsBase64(buffer, read, buffer.Length - read);
                    if (actual == 0)
                        break;
                    read += actual;
                }

                if (totalRead > maxBufferSize - read)
                    throw LogHelper.LogExceptionMessage(new SecurityTokenException("BufferQuotaExceededReadingBase64, maxBufferSize"));

                totalRead += read;
                if (read < buffer.Length)
                    break;
                count = count * 2;
            }
            buffer = new byte[totalRead];
            int offset = 0;
            for (int i = 0; i < bufferCount - 1; i++)
            {
                Buffer.BlockCopy(buffers[i], 0, buffer, offset, buffers[i].Length);
                offset += buffers[i].Length;
            }
            Buffer.BlockCopy(buffers[bufferCount - 1], 0, buffer, offset, totalRead - offset);
            return buffer;
        }

        public static bool TryCreateX509CertificateFromRawData(byte[] rawData, out X509Certificate2 certificate)
        {
            certificate = (rawData == null || rawData.Length == 0) ? null : new X509Certificate2(rawData);
            return certificate != null && certificate.Handle != IntPtr.Zero;
        }

        internal static byte[] DecodeHexString(string hexString)
        {
            hexString = hexString.Trim();

            bool spaceSkippingMode = false;

            int i = 0;
            int length = hexString.Length;

            if ((length >= 2) &&
                (hexString[0] == '0') &&
                ((hexString[1] == 'x') || (hexString[1] == 'X')))
            {
                length = hexString.Length - 2;
                i = 2;
            }

            if (length < 2)
                throw LogHelper.LogExceptionMessage(new FormatException("InvalidHexString"));

            byte[] sArray;

            if (length >= 3 && hexString[i + 2] == ' ')
            {
                if (length % 3 != 2)
                    throw LogHelper.LogExceptionMessage(new FormatException("InvalidHexString"));

                spaceSkippingMode = true;

                // Each hex digit will take three spaces, except the first (hence the plus 1).
                sArray = new byte[length / 3 + 1];
            }
            else
            {
                if (length % 2 != 0)
                    throw LogHelper.LogExceptionMessage(new FormatException("InvalidHexString"));

                spaceSkippingMode = false;

                // Each hex digit will take two spaces
                sArray = new byte[length / 2];
            }

            int digit;
            int rawdigit;
            for (int j = 0; i < hexString.Length; i += 2, j++)
            {
                rawdigit = ConvertHexDigit(hexString[i]);
                digit = ConvertHexDigit(hexString[i + 1]);
                sArray[j] = (byte)(digit | (rawdigit << 4));
                if (spaceSkippingMode)
                    i++;
            }
            return (sArray);
        }

        static int ConvertHexDigit(Char val)
        {
            if (val <= '9' && val >= '0')
                return (val - '0');
            else if (val >= 'a' && val <= 'f')
                return ((val - 'a') + 10);
            else if (val >= 'A' && val <= 'F')
                return ((val - 'A') + 10);
            else
                throw LogHelper.LogExceptionMessage(new FormatException("InvalidHexString"));
        }
    }
}
