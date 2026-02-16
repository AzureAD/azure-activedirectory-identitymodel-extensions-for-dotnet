// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// This file is compiled at build-time by RoslynCodeTaskFactory and runs as an
// MSBuild inline task. It inspects the resolved NuGet package graph for
// Microsoft.IdentityModel.* / System.IdentityModel.* packages and emits a
// build warning when multiple different versions are detected.

// Collect all Microsoft.IdentityModel.* and System.IdentityModel.* packages
// from the resolved RuntimeCopyLocalItems. Each item carries NuGetPackageId and
// NuGetPackageVersion metadata. A deduplication is performed because multiple
// upstream dependencies can come from the same package.
var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
var identityModelPackages = new List<KeyValuePair<string, string>>();

if (ResolvedPackages != null)
{
    foreach (var item in ResolvedPackages)
    {
        var packageId = item.GetMetadata("NuGetPackageId");
        var version = item.GetMetadata("NuGetPackageVersion");

        if (string.IsNullOrEmpty(packageId) || string.IsNullOrEmpty(version))
        {
            continue;
        }

        if (packageId.StartsWith("Microsoft.IdentityModel.", StringComparison.OrdinalIgnoreCase) ||
            packageId.StartsWith("System.IdentityModel.", StringComparison.OrdinalIgnoreCase))
        {
            var key = packageId + "/" + version;
            if (seen.Add(key))
            {
                identityModelPackages.Add(new KeyValuePair<string, string>(packageId, version));
            }
        }
    }
}

if (identityModelPackages.Count <= 1)
{
    return true; // Nothing to compare
}

// Find distinct versions.
var distinctVersions = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
foreach (var pkg in identityModelPackages)
{
    distinctVersions.Add(pkg.Value);
}

if (distinctVersions.Count <= 1)
{
    return true; // All versions match — no warning needed
}

// Parse a NuGet version string into a comparable tuple.
// Strips any prerelease suffix (e.g. "1.2.3-preview456" -> "1.2.3")
// and uses System.Version for numeric comparison. Prerelease versions are
// considered lower than the same base version without a suffix.
Func<string, Tuple<System.Version, bool, string>> parseVersion = (raw) =>
{
    var hyphen = raw.IndexOf('-');
    var isPrerelease = hyphen >= 0;
    var versionPart = isPrerelease ? raw.Substring(0, hyphen) : raw;

    System.Version parsed;
    if (!System.Version.TryParse(versionPart, out parsed))
    {
        parsed = new System.Version(0, 0);
    }

    return Tuple.Create(parsed, !isPrerelease, raw);
};

// Determine the highest version for the upgrade suggestion.
var maxVersion = identityModelPackages
    .Select(item => item.Value)
    .OrderByDescending(item =>
    {
        var version = parseVersion(item);
        return version;
    }, Comparer<Tuple<System.Version, bool, string>>.Default)
    .First();

// Build the warning message.
var sb = new System.Text.StringBuilder();
sb.AppendLine();
sb.AppendLine("All Microsoft.IdentityModel.* and System.IdentityModel.* packages must have the same version to avoid hard-to-diagnose runtime errors.");
sb.AppendLine("The following packages were resolved with different versions:");
sb.AppendLine();

// Sort alphabetically for consistent, readable output.
identityModelPackages.Sort((a, b) => StringComparer.OrdinalIgnoreCase.Compare(a.Key, b.Key));

var packagesToUpgrade = new List<string>();

foreach (var pkg in identityModelPackages)
{
    var marker = StringComparer.OrdinalIgnoreCase.Equals(pkg.Value, maxVersion)
        ? ""
        : " <-- upgrade to " + maxVersion;

    sb.AppendLine("  - " + pkg.Key + " " + pkg.Value + marker);

    if (!StringComparer.OrdinalIgnoreCase.Equals(pkg.Value, maxVersion))
    {
        packagesToUpgrade.Add(pkg.Key);
    }
}

sb.AppendLine();
sb.Append("To fix this, add explicit PackageReference entries for the packages with lower versions to upgrade them to " + maxVersion + ":");
sb.AppendLine();
sb.AppendLine();
sb.AppendLine("  <ItemGroup>");

foreach (var pkgId in packagesToUpgrade)
{
    sb.AppendLine("    <PackageReference Include=\"" + pkgId + "\" Version=\"" + maxVersion + "\" />");
}

sb.AppendLine("  </ItemGroup>");
sb.AppendLine();

Log.LogWarning(null, "IDMODEL001", null, null, 0, 0, 0, 0, sb.ToString());
