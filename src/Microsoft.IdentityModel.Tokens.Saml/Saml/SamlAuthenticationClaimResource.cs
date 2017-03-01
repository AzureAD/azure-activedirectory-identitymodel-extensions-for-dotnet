//-----------------------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
//-----------------------------------------------------------------------------
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Runtime.Serialization;
using Microsoft.IdentityModel.Logging;

namespace Microsoft.IdentityModel.Tokens.Saml
{
    [DataContract]
    public class SamlAuthenticationClaimResource
    {
        [DataMember]
        DateTime authenticationInstant;

        [DataMember]
        string authenticationMethod;

        ReadOnlyCollection<SamlAuthorityBinding> authorityBindings;

        [DataMember]
        string dnsAddress;

        [DataMember]
        string ipAddress;

        [OnDeserialized]
        void OnDeserialized(StreamingContext ctx)
        {
            if (string.IsNullOrEmpty(authenticationMethod))
                throw LogHelper.LogArgumentNullException(nameof(authenticationMethod));
            if (authorityBindings == null)
                throw LogHelper.LogArgumentNullException(nameof(authorityBindings));
        }

        public SamlAuthenticationClaimResource(
            DateTime authenticationInstant,
            string authenticationMethod,
            string dnsAddress,
            string ipAddress
            )
        {
            if (string.IsNullOrEmpty(authenticationMethod))
                throw LogHelper.LogArgumentNullException(nameof(authenticationMethod));

            this.authenticationInstant = authenticationInstant;
            this.authenticationMethod = authenticationMethod;
            this.dnsAddress = dnsAddress;
            this.ipAddress = ipAddress;
            this.authorityBindings = (new List<SamlAuthorityBinding>()).AsReadOnly();
        }

        public SamlAuthenticationClaimResource(
            DateTime authenticationInstant,
            string authenticationMethod,
            string dnsAddress,
            string ipAddress,
            IEnumerable<SamlAuthorityBinding> authorityBindings
            )
            : this(authenticationInstant, authenticationMethod, dnsAddress, ipAddress)
        {
            if (authorityBindings == null)
                throw LogHelper.LogArgumentNullException(nameof(authorityBindings));

            List<SamlAuthorityBinding> tempList = new List<SamlAuthorityBinding>();
            foreach (SamlAuthorityBinding authorityBinding in authorityBindings)
            {
                if (authorityBinding != null)
                    tempList.Add(authorityBinding);
            }
            this.authorityBindings = tempList.AsReadOnly();

        }

        public SamlAuthenticationClaimResource(
            DateTime authenticationInstant,
            string authenticationMethod,
            string dnsAddress,
            string ipAddress,
            ReadOnlyCollection<SamlAuthorityBinding> authorityBindings
            )
            : this(authenticationInstant, authenticationMethod, dnsAddress, ipAddress)
        {
            if (authorityBindings == null)
                throw LogHelper.LogArgumentNullException(nameof(authorityBindings));

            this.authorityBindings = authorityBindings;

        }

        public DateTime AuthenticationInstant
        {
            get
            {
                return this.authenticationInstant;
            }
        }

        public string AuthenticationMethod
        {
            get
            {
                return this.authenticationMethod;
            }
        }

        public ReadOnlyCollection<SamlAuthorityBinding> AuthorityBindings
        {
            get
            {
                return this.authorityBindings;
            }
        }

        // this private member is for serialization only.
        [DataMember]
        List<SamlAuthorityBinding> SamlAuthorityBindings
        {
            get
            {
                List<SamlAuthorityBinding> sab = new List<SamlAuthorityBinding>();
                for (int i = 0; i < this.authorityBindings.Count; ++i)
                {
                    sab.Add(this.authorityBindings[i]);
                }
                return sab;
            }
            set
            {
                if (value != null)
                    this.authorityBindings = value.AsReadOnly();
            }
        }

        public string IPAddress
        {
            get
            {
                return this.ipAddress;
            }
        }

        public string DnsAddress
        {
            get
            {
                return this.dnsAddress;
            }
        }

        public override bool Equals(object obj)
        {
            if (obj == null)
                return false;

            if (ReferenceEquals(this, obj))
                return true;

            SamlAuthenticationClaimResource rhs = obj as SamlAuthenticationClaimResource;
            if (rhs == null)
                return false;

            if ((this.AuthenticationInstant != rhs.AuthenticationInstant) ||
                (this.AuthenticationMethod != rhs.AuthenticationMethod) ||
                (this.AuthorityBindings.Count != rhs.AuthorityBindings.Count) ||
                (this.IPAddress != rhs.IPAddress) ||
                (this.DnsAddress != rhs.DnsAddress))
                return false;

            int i = 0;
            for (i = 0; i < this.AuthorityBindings.Count; ++i)
            {
                bool matched = false;
                for (int j = 0; j < rhs.AuthorityBindings.Count; ++j)
                {
                    if ((this.AuthorityBindings[i].AuthorityKind == rhs.AuthorityBindings[j].AuthorityKind) &&
                        (this.AuthorityBindings[i].Binding == rhs.AuthorityBindings[j].Binding) &&
                        (this.AuthorityBindings[i].Location == rhs.AuthorityBindings[j].Location))
                    {
                        matched = true;
                        break;
                    }
                }

                if (!matched)
                    return false;
            }

            return true;
        }

        public override int GetHashCode()
        {
            return (this.authenticationInstant.GetHashCode() ^ this.authenticationMethod.GetHashCode());
        }
    }
}
