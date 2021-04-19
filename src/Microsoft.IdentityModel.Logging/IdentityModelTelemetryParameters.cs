using System;
using System.Collections.Generic;
using System.Collections.Concurrent;
using System.Reflection;
using System.Net.Http;

namespace Microsoft.IdentityModel.Logging
{
    /// <summary>
    /// Provides a way to add and remove telemetry data.
    /// </summary>
    public static class IdentityModelTelemetryParameters
    {
        internal static readonly ConcurrentDictionary<string, string> parameters = new ConcurrentDictionary<string, string>();
        internal const string skuTelemetry = "x-client-SKU";
        internal const string versionTelemetry = "x-client-Ver";
        internal const string osTelemetry = "x-client-OS";
        internal static List<string> defaultParamNames = new List<string> { skuTelemetry, versionTelemetry };

        /// <summary>
        /// Get the string that represents the client SKU.
        /// </summary>
        public static string ClientSku { get;} =
#if NET45
            "ID_NET45";
#elif NET461
            "ID_NET461";
#elif NET472
            "ID_NET472";
#elif NETSTANDARD2_0
            "ID_NETSTANDARD2_0";
#endif

        /// <summary>
        /// Get the string that represents the client version.
        /// </summary>
        public static string ClientVer { get; } = typeof(IdentityModelTelemetryParameters).GetTypeInfo().Assembly.GetName().Version.ToString();

        static IdentityModelTelemetryParameters()
        {
            parameters[skuTelemetry] = ClientSku;
            parameters[versionTelemetry] = ClientVer;
        }

        /// <summary>
        /// Adds a parameter and its value to the collection of telemetry parameters.
        /// </summary>
        /// <param name="parameter"> Represents the name of the parameter.</param>
        /// <param name="value"> Represents the value of the parameter.</param>
        public static void AddParameter(string parameter, string value)
        {
            if (string.IsNullOrEmpty(parameter))
                throw LogHelper.LogArgumentNullException(nameof(parameter));

            CheckIfDefaultTelemetryParameter(parameter);
            if (value == null)
                RemoveParameter(parameter);
            else
                parameters[parameter] = value;
        }

        /// <summary>
        /// Removes a parameter and its value from the collection of telemetry parameters.
        /// </summary>
        /// <param name="parameter"> Represents the name of the parameter.</param>
        public static void RemoveParameter(string parameter)
        {
            if (string.IsNullOrEmpty(parameter))
                throw LogHelper.LogArgumentNullException(nameof(parameter));

            CheckIfDefaultTelemetryParameter(parameter);
            if (parameters.ContainsKey(parameter))
                parameters.TryRemove(parameter, out _);
        }

        internal static void SetTelemetryData(HttpRequestMessage request)
        {
            if (request == null)
                return;

            foreach (var parameter in parameters)
            {
                // remove this header if it already exists.
                // we don't want to add an additional value in case when a telemetry header already exists, but to overwrite it.
                request.Headers.Remove(parameter.Key);
                request.Headers.Add(parameter.Key, parameter.Value);
            }
        }

        internal static void CheckIfDefaultTelemetryParameter(string parameter)
        {
            if (defaultParamNames.Contains(parameter))
                throw LogHelper.LogExceptionMessage(new ArgumentException(LogHelper.FormatInvariant(LogMessages.MIML10003, defaultParamNames)));

                return;
        }
    }
}
