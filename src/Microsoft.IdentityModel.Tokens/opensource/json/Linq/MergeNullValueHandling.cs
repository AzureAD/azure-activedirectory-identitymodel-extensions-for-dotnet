using System;

namespace Microsoft.IdentityModel.Json.Linq
{
    /// <summary>
    /// Specifies how null value properties are merged.
    /// </summary>
    [Flags]
#pragma warning disable CA1714 // Flags enums should have plural names
    public enum MergeNullValueHandling
#pragma warning restore CA1714 // Flags enums should have plural names
    {
        /// <summary>
        /// The content's null value properties will be ignored during merging.
        /// </summary>
        Ignore = 0,

        /// <summary>
        /// The content's null value properties will be merged.
        /// </summary>
        Merge = 1
    }
}
