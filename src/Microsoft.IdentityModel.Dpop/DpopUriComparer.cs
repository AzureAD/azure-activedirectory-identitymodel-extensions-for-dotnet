// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;

namespace Microsoft.IdentityModel.Dpop;

/// <summary>
/// Component-wise URI comparison aligned with RFC 9449 §4.3 and RFC 3986 §6.2.2.
/// </summary>
/// <remarks>
/// <para>
/// RFC 9449 §4.3 directs servers to compare the proof's <c>htu</c> claim against the
/// HTTP request URI using RFC 3986 §6.2.2 syntax-based normalization.
/// </para>
/// <para>
/// Per RFC 3986 §6.2.2.1, the scheme and host components are compared case-insensitively
/// (and host is additionally subject to IDN normalization). The port is normalized to the
/// scheme's default when omitted (§3.2.3). The path component is compared
/// <strong>case-sensitively</strong> (§3.3 reserves case as significant). Percent-encoded
/// triplets of unreserved characters are decoded for comparison (§6.2.2.2). Query and
/// fragment are excluded per RFC 9449 §4.3.
/// </para>
/// </remarks>
internal static class DpopUriComparer
{
    /// <summary>
    /// Returns <see langword="true"/> when the actual request URI is equivalent to the
    /// URI in the claimed <c>htu</c> value under the comparison rules described in the
    /// type-level remarks.
    /// </summary>
    /// <param name="actual">The actual HTTP request URI. Must be absolute.</param>
    /// <param name="claimed">The URI string from the proof's <c>htu</c> claim.</param>
    /// <returns>
    /// <see langword="true"/> when both URIs are absolute and equivalent;
    /// <see langword="false"/> when <paramref name="claimed"/> cannot be parsed as an
    /// absolute URI, or when any component (scheme, host, port, path) differs.
    /// </returns>
    internal static bool AreEquivalent(Uri actual, string claimed)
    {
        if (actual is null || !actual.IsAbsoluteUri)
            return false;

        if (string.IsNullOrEmpty(claimed))
            return false;

        if (!Uri.TryCreate(claimed, UriKind.Absolute, out Uri claimedUri))
            return false;

        // Scheme + authority (host:port) — case-insensitive per RFC 3986 §6.2.2.1,
        // default-port-aware per §3.2.3, IDN-normalized via .NET's Uri.
        if (Uri.Compare(
                actual,
                claimedUri,
                UriComponents.SchemeAndServer,
                UriFormat.SafeUnescaped,
                StringComparison.OrdinalIgnoreCase) != 0)
        {
            return false;
        }

        // Path — case-sensitive per RFC 3986 §3.3 and §6.2.2.
        // SafeUnescaped normalizes percent-encoding of unreserved chars per §6.2.2.2.
        if (Uri.Compare(
                actual,
                claimedUri,
                UriComponents.Path,
                UriFormat.SafeUnescaped,
                StringComparison.Ordinal) != 0)
        {
            return false;
        }

        return true;
    }
}
