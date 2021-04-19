using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;

namespace Microsoft.IdentityModel.Logging
{
    internal class IdentityModelTelemetryUtils
    {
        internal const string skuTelemetry = "x-client-SKU";
        internal const string versionTelemetry = "x-client-Ver";
        internal readonly static string assemblyVersion = typeof(IdentityModelTelemetryUtils).GetTypeInfo().Assembly.GetName().Version.ToString();
        internal const string platform =
#if NET45
            "ID_NET45";
#elif NET461
            "ID_NET461";
#elif NET472
            "ID_NET472";
#elif NETSTANDARD2_0
            "ID_NETSTANDARD2_0";
#endif

        internal static readonly IReadOnlyDictionary<string, string> telemetryData = new Dictionary<string, string>()
        {
            [skuTelemetry] = platform,
            [versionTelemetry] = assemblyVersion
        };

        internal static void SetTelemetryData(HttpClient httpClient)
        {
            if (httpClient == null)
                return;

            foreach (var telemetryParameter in telemetryData)
            {
                // remove this header if it already exists.
                // we don't want to add an additional value in case when a telemetry header already exists, but to overwrite it.
                if (httpClient.DefaultRequestHeaders.Contains(telemetryParameter.Key))
                    httpClient.DefaultRequestHeaders.Remove(telemetryParameter.Key);

                httpClient.DefaultRequestHeaders.Add(telemetryParameter.Key, telemetryParameter.Value);

            }
        }
    }
}
