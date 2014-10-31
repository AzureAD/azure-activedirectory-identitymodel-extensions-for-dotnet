//-----------------------------------------------------------------------
// Copyright (c) Microsoft Open Technologies, Inc.
// All Rights Reserved
// Apache License 2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// 
// http://www.apache.org/licenses/LICENSE-2.0
// 
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//-----------------------------------------------------------------------

namespace System.IdentityModel.Tokens
{
    using System.Diagnostics.CodeAnalysis;
    using System.Web.Script.Serialization;

    /// <summary>
    /// Definition for a delegate that can be set on <see cref="JsonExtensions.Serializer"/> to control serialization of objects into JSON.
    /// </summary>
    /// <param name="obj">Object to serialize</param>
    /// <returns>The serialized object.</returns>
    public delegate string Serializer(object obj);

    /// <summary>
    /// Definition for a delegate that can be set on <see cref="JsonExtensions.Deserializer"/> to control deserialization JSON into objects.
    /// </summary>
    /// <param name="obj">JSON to deserialize.</param>
    /// <param name="targetType">type expected.</param>
    /// <returns>The deserialized object.</returns>
    public delegate object Deserializer(string obj, Type targetType);

    /// <summary>
    /// Dictionary extensions for serializations
    /// </summary>
    [SuppressMessage("StyleCop.CSharp.DocumentationRules", "SA1600:ElementsMustBeDocumented", Justification = "Suppressed for private fields.")]
    public static class JsonExtensions
    {
        private static JavaScriptSerializer _javaScriptSerializer;
        private static Serializer _serializer;
        private static Deserializer _deserializer;

        static JsonExtensions()
        {
            _javaScriptSerializer = new JavaScriptSerializer();
            _serializer = _javaScriptSerializer.Serialize;
            _deserializer = _javaScriptSerializer.Deserialize;
        }

        /// <summary>
        /// Gets or sets a <see cref="Serializer"/> to use when serializing objects to JSON.
        /// </summary>
        /// <exception cref="ArgumentNullException">if 'value' is null.</exception>
        public static Serializer Serializer
        {
            get
            {
                return _serializer;
            }
            set
            {
                if (value == null)
                    throw new ArgumentNullException("value");

                _serializer = value;
            }
        }

        /// <summary>
        /// Gets or sets a <see cref="Deserializer"/> to use when deserializing objects from JSON.
        /// </summary>
        /// <exception cref="ArgumentNullException">if 'value' is null.</exception>

        public static Deserializer Deserializer
        {
            get
            {
                return _deserializer;
            }
            set
            {
                if (value == null)
                    throw new ArgumentNullException("value");

                _deserializer = value;
            }
        }

        /// <summary>
        /// Serializes an object to JSON.
        /// </summary>
        /// <param name="value">The object to serialize</param>
        /// <returns>the object as JSON.</returns>
        public static string SerializeToJson(object value)
        {
            return Serializer(value);
        }

        /// <summary>
        /// Deserialzes JSON into an instance of type T.
        /// </summary>
        /// <typeparam name="T">the object type.</typeparam>
        /// <param name="jsonString">the JSON to deserialze.</param>
        /// <returns>a new instance of type T.</returns>
        public static T DeserializeFromJson<T>(string jsonString) where T : class
        {
            return Deserializer(jsonString, typeof(T)) as T;
        }

        /// <summary>
        /// Deserialzes JSON into an instance of <see cref="JwtHeader"/>.
        /// </summary>
        /// <param name="jsonString">the JSON to deserialze.</param>
        /// <returns>a new instance <see cref="JwtHeader"/>.</returns>
        public static JwtHeader DeserializeJwtHeader(string jsonString)
        {
            return Deserializer(jsonString, typeof(JwtHeader)) as JwtHeader;
        }

        /// <summary>
        /// Deserialzes JSON into an instance of <see cref="JwtPayload"/>.
        /// </summary>
        /// <param name="jsonString">the JSON to deserialze.</param>
        /// <returns>a new instance <see cref="JwtPayload"/>.</returns>
        public static JwtPayload DeserializeJwtPayload(string jsonString)
        {
            return Deserializer(jsonString, typeof(JwtPayload)) as JwtPayload;
        }
    }
}
