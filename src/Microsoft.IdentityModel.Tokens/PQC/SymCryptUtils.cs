// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Runtime.InteropServices;

/// <summary>
/// Some utilities related to integrating with SymCrypt.dll.
/// Once we start moving closer to release, some of these utilities will be moved to a more appropriate location or removed.
/// </summary>
internal static class SymCryptUtils
{
    public static byte[] StructToByteArray<T>(T str) where T : struct
    {
        int size = Marshal.SizeOf(str);
        byte[] arr = new byte[size];
        IntPtr ptr = Marshal.AllocHGlobal(size);

        try
        {
            Marshal.StructureToPtr(str, ptr, true);
            Marshal.Copy(ptr, arr, 0, size);
        }
        finally
        {
            Marshal.FreeHGlobal(ptr);
        }

        return arr;
    }

    /// <summary>
    /// Compares two byte arrays for equality
    /// </summary>
    /// <returns>true if the arrays are the same size with same values.</returns>
    public static bool AreEqual(byte[] bytesA, byte[] bytesB)
    {
        if (bytesA == null && bytesB != null)
            return false;

        if (bytesA != null && bytesB == null)
            return false;

        if (bytesA == null && bytesB == null)
            return true;

        if (bytesA.Length != bytesB.Length)
            return false;

        for (int i = 0; i < bytesA.Length; i++)
            if (bytesA[i] != bytesB[i])
                return false;

        return true;
    }
}

