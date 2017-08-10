using System;
using System.Collections.Generic;

namespace Microsoft.IdentityModel.Tests
{
    public class CompareContext
    {
        List<string> _diffs = new List<string>();

        public static CompareContext Default = new CompareContext();

        public CompareContext()
        {
        }

        public CompareContext(string title)
        {
            Title = title;
        }

        public CompareContext(CompareContext other)
        {
            if (other == null)
                return;

            ExpectRawData = other.ExpectRawData;
            IgnoreClaimsIdentityType = other.IgnoreClaimsIdentityType;
            IgnoreClaimsPrincipalType = other.IgnoreClaimsPrincipalType;
            IgnoreClaimType = other.IgnoreClaimType;
            IgnoreProperties = other.IgnoreProperties;
            IgnoreSubject = other.IgnoreSubject;
            IgnoreType = other.IgnoreType;
            StringComparison = other.StringComparison;
        }

        public List<string> Diffs { get { return _diffs; } }

        public bool ExpectRawData { get; set; }

        /// <summary>
        /// Adds diffs and returns if any diffs were added.
        /// </summary>
        /// <param name="context"></param>
        /// <returns>true if any diffs were added.</returns>
        public bool Merge(CompareContext context)
        {
            return Merge(null, context);
        }

        public bool Merge(string title, CompareContext context)
        {
            if (context == null)
                return false;

            if (context.Diffs.Count > 0)
            {
                if (!string.IsNullOrEmpty(title))
                    _diffs.Add(title);
                _diffs.AddRange(context.Diffs);
            }

            return (context.Diffs.Count == 0);
        }

        public bool IgnoreClaimsIdentityType { get; set; }

        public bool IgnoreClaimsPrincipalType { get; set; }

        public bool IgnoreClaimType { get; set; }

        public bool IgnoreProperties { get; set; }

        public bool IgnoreSubject { get; set; } = true;

        public bool IgnoreType { get; set; } = true;

        public StringComparison StringComparison { get; set; } = System.StringComparison.Ordinal;

        public string Title { get; set; }
    }
}
