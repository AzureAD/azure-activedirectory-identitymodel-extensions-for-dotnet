//------------------------------------------------------------
// Copyright (c) Microsoft Corporation.  All rights reserved.
//------------------------------------------------------------

namespace Microsoft.IdentityModel.Xml
{
    using System.Xml;

    public abstract class Transform
    {
        protected Transform()
        {}

        public virtual string Algorithm { get; set; }

        public virtual bool NeedsInclusiveContext
        {
            get { return false; }
        }

        public abstract object Process(object input, SignatureResourcePool resourcePool);

        public abstract byte[] ProcessAndDigest(object input, SignatureResourcePool resourcePool, string digestAlgorithm);

        public abstract void ReadFrom(XmlDictionaryReader reader, bool preserveComments);

        public abstract void WriteTo(XmlDictionaryWriter writer);
    }
}
