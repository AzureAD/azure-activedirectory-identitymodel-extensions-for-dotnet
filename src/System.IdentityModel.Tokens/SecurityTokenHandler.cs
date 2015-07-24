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

using System;
using System.Xml;

namespace System.IdentityModel.Tokens
{
    /// <summary>
    /// Defines the interface for a Security Token Handler.
    /// </summary>
    public abstract class SecurityTokenHandler
    {
        /// <summary>
        /// Creates an instance of <see cref="SecurityTokenHandler"/>
        /// </summary>
        protected SecurityTokenHandler()
        {
        }

        public virtual SecurityKeyIdentifierClause CreateSecurityTokenReference(SecurityToken token, bool attached)
        {
            throw new NotImplementedException();
        }

        public virtual SecurityToken CreateToken(SecurityTokenDescriptor tokenDescriptor)
        {
            throw new NotImplementedException();
        }

        /// <summary>
        /// Gets a value indicating whether this handler supports validation of tokens 
        /// handled by this instance.
        /// </summary>v
        /// <returns>'True' if the instance is capable of SecurityToken
        /// validation.</returns>
        public virtual bool CanValidateToken
        {
            get { return false; }
        }

        /// <summary>
        /// Gets a value indicating whether the class provides serialization functionality to serialize token handled 
        /// by this instance.
        /// </summary>
        /// <returns>true if the WriteToken method can serialize this token.</returns>
        public virtual bool CanWriteToken
        {
            get { return false; }
        }

        /// <summary>
        /// Gets the System.Type of the SecurityToken this instance handles.
        /// </summary>
        public abstract Type TokenType
        {
            get;
        }

        /// <summary>
        /// Indicates whether the current token string can be read as a token 
        /// of the type handled by this instance.
        /// </summary>
        /// <param name="tokenString">The token string thats needs to be read.</param>
        /// <returns>'True' if the ReadToken method can parse the token string.</returns>
        public virtual bool CanReadToken(string tokenString)
        {
            return false;
        }
        
        /// <summary>
        /// Deserializes from string a token of the type handled by this instance.
        /// </summary>
        /// <param name="tokenString">The string to be deserialized.</param>
        /// <returns>SecurityToken instance which represents the serialized token.</returns>
        public virtual SecurityToken ReadToken(string tokenString)
        {
            return null;
        }

        public virtual SecurityToken ReadToken(XmlReader reader)
        {
            return null;
        }

        /// <summary>
        /// Serializes to string a token of the type handled by this instance.
        /// </summary>
        /// <param name="token">A token of type TokenType.</param>
        /// <returns>The serialized token.</returns>
        public virtual string WriteToken(SecurityToken token)
        {
            return null;
        }

        /// <summary>
        /// Serializes to XML a token of the type handled by this instance.
        /// </summary>
        /// <param name="writer">The XML writer.</param>
        /// <param name="token">A token of type <see cref="TokenType"/>.</param>
        public abstract void WriteToken(XmlWriter writer, SecurityToken token);

        public abstract SecurityToken ReadToken(XmlReader reader, TokenValidationParameters validationParameters);
    }
}
