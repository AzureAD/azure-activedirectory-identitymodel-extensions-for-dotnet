// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

namespace Microsoft.IdentityModel.Logging;

internal static class UtilExtensions
{
    public static bool IsNullOrEmpty(this object[] array)
    {
        return (array?.Length ?? 0) == 0;
    }
}
