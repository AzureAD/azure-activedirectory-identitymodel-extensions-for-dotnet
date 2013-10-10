//------------------------------------------------------------------------------
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//------------------------------------------------------------------------------

using System;
using System.Globalization;
using System.Runtime.Serialization.Json;
using System.Web.Script.Serialization;

namespace System.IdentityModel.Tokens
{
    internal static class JsonExtensions
    {
        public static string SerializeToJson( this object value )
        {
            JavaScriptSerializer serializer = new JavaScriptSerializer();
            return serializer.Serialize( value );
        }

        public static T DeserializeFromJson<T>( this string value )
        {
            JavaScriptSerializer serializer = new JavaScriptSerializer();
            return serializer.Deserialize<T>( value );
        }

        public static JwtHeader DeserializeJwtHeader( this string value )
        {
            return DeserializeFromJson<JwtHeader>( value );
        }

        public static JwtPayload DeserializeJwtPayload( this string value )
        {
            return DeserializeFromJson<JwtPayload>( value );
        }
    }
}
