//-----------------------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
//-----------------------------------------------------------------------------

using System.Runtime.Serialization;
using Microsoft.IdentityModel.Logging;

namespace Microsoft.IdentityModel.Tokens.Saml
{
    [DataContract]
    public class SamlNameIdentifierClaimResource
    {
        [DataMember]
        string nameQualifier;

        [DataMember]
        string format;

        [DataMember]
        string name;

        [OnDeserialized]
        void OnDeserialized(StreamingContext ctx)
        {
            if (string.IsNullOrEmpty(this.name))
                throw LogHelper.LogArgumentNullException(nameof(name));
        }

        public SamlNameIdentifierClaimResource(string name, string nameQualifier, string format)
        {
            if (string.IsNullOrEmpty(name))
                throw LogHelper.LogArgumentNullException(nameof(name));

            this.name = name;
            this.nameQualifier = nameQualifier;
            this.format = format;
        }

        public string NameQualifier
        { 
            get 
            { 
                return this.nameQualifier; 
            } 
        }

        public string Format
        { 
            get 
            { 
                return this.format; 
            } 
        }

        public string Name
        { 
            get 
            { 
                return this.name;
            } 
        }

        public override bool Equals(object obj)
        {
            if (obj == null)
                return false;

            if (ReferenceEquals(this, obj))
                return true;

            SamlNameIdentifierClaimResource rhs = obj as SamlNameIdentifierClaimResource;
            if (rhs == null)
                return false;

            return ((this.nameQualifier == rhs.nameQualifier) && (this.format == rhs.format) && (this.name == rhs.name));
        }

        public override int GetHashCode()
        {
            return this.name.GetHashCode();
        }

    }
}
