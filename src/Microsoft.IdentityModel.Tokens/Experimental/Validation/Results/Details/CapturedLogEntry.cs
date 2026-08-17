// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using Microsoft.IdentityModel.Abstractions;

#nullable enable
namespace Microsoft.IdentityModel.Tokens.Experimental
{
    /// <summary>
    /// A single structured, PII-aware informational log entry captured during result-based token validation.
    /// </summary>
    /// <remarks>
    /// Part of the logging contract for the new validation pipeline (issue #3455). Validators record entries
    /// on the <see cref="CallContext"/> instead of emitting directly; the handler drains and emits them
    /// (converting to <see cref="Abstractions.LogEntry"/> at the sink). The <see cref="MessageDetail"/> is
    /// formatted lazily and honors <c>MarkAsNonPII</c>, so no message string is built unless and until the
    /// entry is emitted. This is the informational-log analog of the failure-path <see cref="ValidationError"/>.
    /// </remarks>
    public readonly struct CapturedLogEntry : IEquatable<CapturedLogEntry>
    {
        /// <summary>
        /// Creates a new <see cref="CapturedLogEntry"/>.
        /// </summary>
        /// <param name="level">The level the entry should be emitted at.</param>
        /// <param name="messageDetail">The lazily-formatted, PII-aware message.</param>
        public CapturedLogEntry(EventLogLevel level, MessageDetail messageDetail)
        {
            Level = level;
            MessageDetail = messageDetail;
        }

        /// <summary>
        /// The <see cref="EventLogLevel"/> the entry should be emitted at.
        /// </summary>
        public EventLogLevel Level { get; }

        /// <summary>
        /// The lazily-formatted, PII-aware message.
        /// </summary>
        public MessageDetail MessageDetail { get; }

        /// <inheritdoc/>
        public bool Equals(CapturedLogEntry other) =>
            Level == other.Level && ReferenceEquals(MessageDetail, other.MessageDetail);

        /// <inheritdoc/>
        public override bool Equals(object? obj) => obj is CapturedLogEntry other && Equals(other);

        /// <inheritdoc/>
        public override int GetHashCode() =>
            (((int)Level) * 397) ^ (MessageDetail?.GetHashCode() ?? 0);

        /// <summary>Determines whether two <see cref="CapturedLogEntry"/> values are equal.</summary>
        public static bool operator ==(CapturedLogEntry left, CapturedLogEntry right) => left.Equals(right);

        /// <summary>Determines whether two <see cref="CapturedLogEntry"/> values are not equal.</summary>
        public static bool operator !=(CapturedLogEntry left, CapturedLogEntry right) => !left.Equals(right);
    }
}
#nullable restore
