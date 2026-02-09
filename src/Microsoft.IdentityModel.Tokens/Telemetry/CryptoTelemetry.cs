// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#nullable enable
using System;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
#if NET8_0_OR_GREATER
using System.Buffers;
#endif
using Microsoft.IdentityModel.Tokens;

namespace Microsoft.IdentityModel.Telemetry;

/// <summary>
/// Provides utility methods for telemetry and analytics purposes.
/// </summary>
public static class CryptoTelemetry
{
    internal static bool RecordSignatureValidationTelemetry { get; set; }
    private static volatile string[] _trackedIssuersArray = Array.Empty<string>();
    private const string OtherIssuersLabel = "other";

    /// <summary>
    /// Enables or disables telemetry for signature validation and configures related settings.
    /// </summary>
    /// <param name="enable">Indicates whether to enable signature validation telemetry.</param>
    /// <param name="trackedIssuers">An optional list of issuer hosts to track in telemetry. Issuers not in this list will be reported as "other".</param>
    public static void EnableSignatureValidationTelemetry(
        bool enable,
        string[]? trackedIssuers)
    {
        RecordSignatureValidationTelemetry = enable;
        TrackedIssuers = trackedIssuers ?? Array.Empty<string>();
    }

    /// <summary>
    /// Gets or sets the allowlist of issuer hosts to track in telemetry.
    /// </summary>
    /// <remarks>
    /// <para>Issuer hosts not in this list will be reported as "other" to prevent cardinality explosion in telemetry systems.</para>
    /// <para>When set to null or empty, all issuers will be reported as "other".</para>
    /// <para>Example: new[] { "login.microsoftonline.com", "accounts.google.com" }</para>
    /// </remarks>
    private static string[] TrackedIssuers
    {
        get => _trackedIssuersArray;
        set
        {
            if (value == null || value.Length == 0)
            {
                _trackedIssuersArray = Array.Empty<string>();
            }
            else
            {
                _trackedIssuersArray = value
                    .Where(h => !string.IsNullOrWhiteSpace(h))
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .ToArray();
            }
        }
    }

#if NET8_0_OR_GREATER
    private static readonly SearchValues<char> _hostDelimiters = SearchValues.Create(['/', '?', ':']);
#endif

    private static class KeyAlgorithmIds
    {
        public const string Rsa2048 = "RSA-2048";
        public const string Rsa3072 = "RSA-3072";
        public const string Rsa4096 = "RSA-4096";
        public const string RsaUnknown = "RSA-UNKNOWN";

        public const string EcdsaP256 = "ECDSA-P256";
        public const string EcdsaP384 = "ECDSA-P384";
        public const string EcdsaP521 = "ECDSA-P521";
        public const string EcdsaUnknown = "ECDSA-UNKNOWN";

        public const string Symmetric128 = "SYM-128";
        public const string Symmetric192 = "SYM-192";
        public const string Symmetric256 = "SYM-256";
        public const string Symmetric384 = "SYM-384";
        public const string Symmetric512 = "SYM-512";
        public const string SymmetricUnknown = "SYM-UNKNOWN";

        public const string Unknown = "UNKNOWN"; // Key type is not recognized.
        public const string NoKey = "NO-KEY"; // Used when no key is found or provided to differentiate from unknown key types
    }

    internal static string GetKeyAlgorithmId(SecurityKey key)
    {
        return key switch
        {
            null => KeyAlgorithmIds.NoKey,

            RsaSecurityKey rsa => rsa.KeySize switch
            {
                2048 => KeyAlgorithmIds.Rsa2048,
                3072 => KeyAlgorithmIds.Rsa3072,
                4096 => KeyAlgorithmIds.Rsa4096,
                _ => KeyAlgorithmIds.RsaUnknown
            },

            ECDsaSecurityKey ecdsa => ecdsa.KeySize switch
            {
                256 => KeyAlgorithmIds.EcdsaP256,
                384 => KeyAlgorithmIds.EcdsaP384,
                521 => KeyAlgorithmIds.EcdsaP521,
                _ => KeyAlgorithmIds.EcdsaUnknown
            },

            SymmetricSecurityKey symmetric => symmetric.KeySize switch
            {
                128 => KeyAlgorithmIds.Symmetric128,
                192 => KeyAlgorithmIds.Symmetric192,
                256 => KeyAlgorithmIds.Symmetric256,
                384 => KeyAlgorithmIds.Symmetric384,
                512 => KeyAlgorithmIds.Symmetric512,
                _ => KeyAlgorithmIds.SymmetricUnknown
            },

            X509SecurityKey x509 => x509.KeySize switch
            {
                2048 => KeyAlgorithmIds.Rsa2048,
                3072 => KeyAlgorithmIds.Rsa3072,
                4096 => KeyAlgorithmIds.Rsa4096,
                256 => KeyAlgorithmIds.EcdsaP256,
                384 => KeyAlgorithmIds.EcdsaP384,
                521 => KeyAlgorithmIds.EcdsaP521,
                _ => x509.PublicKey is RSA
                    ? KeyAlgorithmIds.RsaUnknown
                    : x509.PublicKey is ECDsa
                        ? KeyAlgorithmIds.EcdsaUnknown
                        : KeyAlgorithmIds.Unknown
            },

            JsonWebKey jwk => GetJsonWebKeyAlgorithmId(jwk),

            // EdDSA, MLDSA and other key types can be added here when needed.
            _ => KeyAlgorithmIds.Unknown
        };
    }

    private static string GetJsonWebKeyAlgorithmId(JsonWebKey jwk)
    {
        if (jwk.ConvertedSecurityKey != null)
            return GetKeyAlgorithmId(jwk.ConvertedSecurityKey);

        return jwk.Kty switch
        {
            JsonWebAlgorithmsKeyTypes.RSA => jwk.KeySize switch
            {
                2048 => KeyAlgorithmIds.Rsa2048,
                3072 => KeyAlgorithmIds.Rsa3072,
                4096 => KeyAlgorithmIds.Rsa4096,
                _ => KeyAlgorithmIds.RsaUnknown
            },
            JsonWebAlgorithmsKeyTypes.EllipticCurve => jwk.KeySize switch
            {
                256 => KeyAlgorithmIds.EcdsaP256,
                384 => KeyAlgorithmIds.EcdsaP384,
                521 => KeyAlgorithmIds.EcdsaP521,
                _ => KeyAlgorithmIds.EcdsaUnknown
            },
            JsonWebAlgorithmsKeyTypes.Octet => jwk.KeySize switch
            {
                128 => KeyAlgorithmIds.Symmetric128,
                192 => KeyAlgorithmIds.Symmetric192,
                256 => KeyAlgorithmIds.Symmetric256,
                384 => KeyAlgorithmIds.Symmetric384,
                512 => KeyAlgorithmIds.Symmetric512,
                _ => KeyAlgorithmIds.SymmetricUnknown
            },
            _ => KeyAlgorithmIds.Unknown
        };
    }

    /// <summary>
    /// Gets the issuer host for telemetry, returning "other" if not in the tracked issuers allowlist.
    /// </summary>
    /// <param name="issuer">The full issuer URI.</param>
    /// <returns>The issuer host if in the allowlist, otherwise "other".</returns>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    internal static string GetTrackedIssuerOrOther(string issuer)
    {
        string[] trackedIssuers = TrackedIssuers;

        if (trackedIssuers.Length == 0 || string.IsNullOrWhiteSpace(issuer))
            return OtherIssuersLabel;

        string host = ExtractHostFromIssuer(issuer);

        if (string.IsNullOrWhiteSpace(host))
            return OtherIssuersLabel;

        return trackedIssuers.Contains(host, StringComparer.OrdinalIgnoreCase)
            ? host
            : OtherIssuersLabel;
    }

    internal static string ExtractHostFromIssuer(string issuer)
    {
        if (string.IsNullOrEmpty(issuer))
            return string.Empty;

        // Skip past the scheme (e.g., "http://", "https://") if present.
#if NET6_0_OR_GREATER
        // On .NET 6+, string literals can be implicitly converted to ReadOnlySpan<char>
        ReadOnlySpan<char> issuerSpan = issuer;
        int schemeIndex = issuerSpan.IndexOf("://");
#else
        // On older frameworks, explicit conversion is required
        ReadOnlySpan<char> issuerSpan = issuer.AsSpan();
        int schemeIndex = issuerSpan.IndexOf("://".AsSpan());
#endif
        if (schemeIndex >= 0)
            issuerSpan = issuerSpan.Slice(schemeIndex + 3);

#if NET8_0_OR_GREATER
        // On .NET 8+, use SearchValues for optimized multi-character search
        int firstDelimiterIndex = issuerSpan.IndexOfAny(_hostDelimiters);

        if (firstDelimiterIndex < 0)
        {
            // No delimiters found - entire span is the host
            return issuerSpan.ToString();
        }

        // Determine what delimiter was found and extract host accordingly
        char delimiter = issuerSpan[firstDelimiterIndex];

        if (delimiter == ':')
        {
            // Port delimiter found - check if there's a path/query after it
            ReadOnlySpan<char> afterColon = issuerSpan.Slice(firstDelimiterIndex + 1);
            int pathOrQuery = afterColon.IndexOfAny(['/', '?']);

            if (pathOrQuery >= 0)
            {
                // There's a path/query after the port - host is before the colon
                return issuerSpan.Slice(0, firstDelimiterIndex).ToString();
            }
            // Port at the end - host is before the colon
            return issuerSpan.Slice(0, firstDelimiterIndex).ToString();
        }

        // Path or query delimiter found - extract host before it, strip port if present
        ReadOnlySpan<char> hostPart = issuerSpan.Slice(0, firstDelimiterIndex);
        int portIndex = hostPart.IndexOf(':');

        if (portIndex > 0)
            hostPart = hostPart.Slice(0, portIndex);

        return hostPart.ToString();
#else
        // Find the end of the host (first '/' or '?', or end of string).
        // Optimize for the common case where a path exists.
        int hostEnd;
        int pathStart = issuerSpan.IndexOf('/');
        if (pathStart >= 0)
        {
            // Path found - use it as host end (query would come after path if present).
            hostEnd = pathStart;
        }
        else
        {
            // No path - check for query parameter.
            int queryStart = issuerSpan.IndexOf('?');
            hostEnd = queryStart >= 0 ? queryStart : issuerSpan.Length;
        }

        if (hostEnd == 0)
            return string.Empty;

        ReadOnlySpan<char> host = issuerSpan.Slice(0, hostEnd);

        // Strip port number to reduce cardinality (e.g., example.com:8080 -> example.com).
        int portIndex = host.IndexOf(':');
        if (portIndex > 0)
            host = host.Slice(0, portIndex);

        return host.ToString();
#endif
    }
}
