// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

#if NET45
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Security.Claims;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using Microsoft.IdentityModel.Json.Linq;
using Microsoft.IdentityModel.Json;

namespace Microsoft.IdentityModel.JsonWebTokens
{
    internal class JsonClaimSet
    {
        IList<Claim> _claims;

        public JsonClaimSet()
        {
            RootElement = new JObject();
        }

        public JsonClaimSet(byte[] jsonBytes)
        {
            RootElement = JObject.Parse(Encoding.UTF8.GetString(jsonBytes));
        }

        public JsonClaimSet(string json)
        {
            RootElement = JObject.Parse(json);
        }

        public bool TryGetValue(string claimName, out JToken json)
        {
            return RootElement.TryGetValue(claimName, out json);
        }

        public JObject RootElement { get; }

        internal IList<Claim> Claims(string issuer)
        {
            if (_claims != null)
                return _claims;

            _claims = new List<Claim>();

            if (!RootElement.HasValues)
                return _claims;

            // there is some code redundancy here that was not factored as this is a high use method. Each identity received from the host will pass through here.
            foreach (var entry in RootElement)
            {
                if (entry.Value == null)
                {
                    _claims.Add(new Claim(entry.Key, string.Empty, JsonClaimValueTypes.JsonNull, issuer, issuer));
                    continue;
                }

                if (entry.Value.Type is JTokenType.String)
                {
                    var claimValue = entry.Value.ToObject<string>();
                    _claims.Add(new Claim(entry.Key, claimValue, ClaimValueTypes.String, issuer, issuer));
                    continue;
                }

                var jtoken = entry.Value;
                if (jtoken != null)
                {
                    AddClaimsFromJToken(_claims, entry.Key, jtoken, issuer);
                    continue;
                }
            }

            return _claims;
        }

        private static Claim CreateClaimFromJToken(string key, string issuer, JToken jToken)
        {
            if (jToken.Type == JTokenType.Null)
                return new Claim(key, string.Empty, JsonClaimValueTypes.JsonNull, issuer, issuer);
            else if (jToken.Type is JTokenType.Object)
                return new Claim(key, jToken.ToString(Formatting.None), JsonClaimValueTypes.Json, issuer, issuer);
            else if (jToken.Type is JTokenType.Array)
                return new Claim(key, jToken.ToString(Formatting.None), JsonClaimValueTypes.JsonArray, issuer, issuer);
            else if (jToken is JValue jvalue)
            {
                // String is special because item.ToString(Formatting.None) will result in "/"string/"". The quotes will be added.
                // Boolean needs item.ToString otherwise 'true' => 'True'
                if (jvalue.Type is JTokenType.String)
                    return new Claim(key, jvalue.Value.ToString(), ClaimValueTypes.String, issuer, issuer);
                // DateTime claims require special processing. jTokenValue.ToString(Formatting.None) will result in "\"dateTimeValue\"". The quotes will be added.
                else if (jvalue.Value is DateTime dateTimeValue)
                    return new Claim(key, dateTimeValue.ToUniversalTime().ToString("o", CultureInfo.InvariantCulture), ClaimValueTypes.DateTime, issuer);
                else
                    return new Claim(key, jToken.ToString(Formatting.None), GetClaimValueType(jvalue.Value), issuer, issuer);
            }
            else
                return new Claim(key, jToken.ToString(Formatting.None), GetClaimValueType(jToken), issuer, issuer);
        }

        private static void AddClaimsFromJToken(IList<Claim> claims, string claimType, JToken jtoken, string issuer)
        {
            if (jtoken.Type is JTokenType.Object)
            {
                claims.Add(new Claim(claimType, jtoken.ToString(Formatting.None), JsonClaimValueTypes.Json, issuer, issuer));
            }
            else if (jtoken.Type is JTokenType.Array)
            {
                var jarray = jtoken as JArray;
                foreach (var item in jarray)
                {
                    switch (item.Type)
                    {
                        case JTokenType.Object:
                            claims.Add(new Claim(claimType, item.ToString(Formatting.None), JsonClaimValueTypes.Json, issuer, issuer));
                            break;

                        // only go one level deep on arrays.
                        case JTokenType.Array:
                            claims.Add(new Claim(claimType, item.ToString(Formatting.None), JsonClaimValueTypes.JsonArray, issuer, issuer));
                            break;

                        default:
                            AddDefaultClaimFromJToken(claims, claimType, item, issuer);
                            break;
                    }
                }
            }
            else
            {
                AddDefaultClaimFromJToken(claims, claimType, jtoken, issuer);
            }
        }

        private static void AddDefaultClaimFromJToken(IList<Claim> claims, string claimType, JToken jtoken, string issuer)
        {
            if (jtoken is JValue jvalue)
            {
                // String is special because item.ToString(Formatting.None) will result in "/"string/"". The quotes will be added.
                // Boolean needs item.ToString otherwise 'true' => 'True'
                if (jvalue.Type is JTokenType.String)
                    claims.Add(new Claim(claimType, jvalue.Value.ToString(), ClaimValueTypes.String, issuer, issuer));
                // DateTime claims require special processing. jtoken.ToString(Formatting.None) will result in "\"dateTimeValue\"". The quotes will be added.
                else if (jvalue.Value is DateTime dateTimeValue)
                    claims.Add(new Claim(claimType, dateTimeValue.ToUniversalTime().ToString("o", CultureInfo.InvariantCulture), ClaimValueTypes.DateTime, issuer, issuer));
                else
                    claims.Add(new Claim(claimType, jtoken.ToString(Formatting.None), JsonClaimSet.GetClaimValueType(jvalue.Value), issuer, issuer));
            }
            else
                claims.Add(new Claim(claimType, jtoken.ToString(Formatting.None), JsonClaimSet.GetClaimValueType(jtoken), issuer, issuer));
        }

        internal bool TryGetClaim(string key, string issuer, out Claim claim)
        {
            if (!RootElement.TryGetValue(key, out var jTokenValue))
            {
                claim = null;
                return false;
            }

            claim = CreateClaimFromJToken(key, issuer, jTokenValue);
            return true;
        }

        internal Claim GetClaim(string key, string issuer)
        {
            if (key == null)
                throw new ArgumentNullException(nameof(key));

            if (!RootElement.TryGetValue(key, out var jTokenValue))
                throw LogHelper.LogExceptionMessage(new ArgumentException(LogHelper.FormatInvariant(LogMessages.IDX14304, key)));

            return CreateClaimFromJToken(key, issuer, jTokenValue);
        }

        public static string GetClaimValueType(object obj)
        {
            if (obj == null)
                return JsonClaimValueTypes.JsonNull;

            var objType = obj.GetType();

            if (objType == typeof(string))
                return ClaimValueTypes.String;

            if (objType == typeof(int))
                return ClaimValueTypes.Integer;

            if (objType == typeof(bool))
                return ClaimValueTypes.Boolean;

            if (objType == typeof(double))
                return ClaimValueTypes.Double;

            if (objType == typeof(long))
            {
                long l = (long)obj;
                if (l >= int.MinValue && l <= int.MaxValue)
                    return ClaimValueTypes.Integer;

                return ClaimValueTypes.Integer64;
            }

            if (objType == typeof(DateTime))
                return ClaimValueTypes.DateTime;

            if (objType == typeof(JObject))
                return JsonClaimValueTypes.Json;

            if (objType == typeof(JArray))
                return JsonClaimValueTypes.JsonArray;
            return objType.ToString();
        }

        internal string GetStringValue(string key)
        {
            if (RootElement.TryGetValue(key, out JToken jtoken) && jtoken.Type == JTokenType.String)
                return (string)jtoken;

            return string.Empty;
        }

        internal DateTime GetDateTime(string key)
        {
            if (!RootElement.TryGetValue(key, out JToken jToken))
                return DateTime.MinValue;

            return EpochTime.DateTime(Convert.ToInt64(Math.Truncate(Convert.ToDouble(ParseTimeValue(key, jToken), CultureInfo.InvariantCulture))));
        }

        public T GetValue<T>(string key)
        {
            if (!RootElement.TryGetValue(key, out var jTokenValue))
                throw LogHelper.LogExceptionMessage(new ArgumentException(LogHelper.FormatInvariant(LogMessages.IDX14304, key)));

            T value;
            if (jTokenValue.Type == JTokenType.Null)
            {
                if (Nullable.GetUnderlyingType(typeof(T)) != null)
                    value = (T)(object)null;
                else
                    value = default;
            }
            else
            {
                try
                {
                    value = jTokenValue.ToObject<T>();
                }
                catch (Exception ex)
                {
                    throw LogHelper.LogExceptionMessage(new ArgumentException(LogHelper.FormatInvariant(LogMessages.IDX14305, key, typeof(T), jTokenValue.Type, jTokenValue.ToString()), ex));
                }
            }

            return value;
        }

        public bool TryGetValue<T>(string key, out T value)
        {
            if (RootElement.TryGetValue(key, out var jTokenValue))
            {
                try
                {
                    value = jTokenValue.ToObject<T>();
                    return true;
                }
#pragma warning disable CA1031 // Do not catch general exception types
                catch (Exception)
#pragma warning restore CA1031 // Do not catch general exception types
                {
                    value = default(T);
                    return false;
                }
            }
            else
            {
                value = default;
            }

            return false;
        }

        internal bool HasClaim(string claimName)
        {
            return RootElement.TryGetValue(claimName, out _);
        }

        private static long ParseTimeValue(string claimName, JToken jToken)
        {
            if (jToken.Type == JTokenType.Integer || jToken.Type == JTokenType.Float)
            {
                return (long)jToken;
            }
            else if (jToken.Type == JTokenType.String)
            {
                if (long.TryParse((string)jToken, out long resultLong))
                    return resultLong;

                if (float.TryParse((string)jToken, out float resultFloat))
                    return (long)resultFloat;

                if (double.TryParse((string)jToken, out double resultDouble))
                    return (long)resultDouble;
            }

            throw LogHelper.LogExceptionMessage(new FormatException(LogHelper.FormatInvariant(LogMessages.IDX14300, claimName, jToken.ToString(), typeof(long))));
        }
    }
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
}
#endif
