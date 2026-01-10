// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using System.Diagnostics;

#nullable enable

namespace Microsoft.IdentityModel.Tokens.Experimental
{
    internal sealed class IdentityModelStackFrame : StackFrame
    {
        private readonly string _memberName;
        private readonly int _lineNumber;
        private readonly int _columnNumber;
        private readonly string _fileName;
        private readonly int _nativeOffset;
        private readonly int _ilOffset;

        public IdentityModelStackFrame(
            int ilOffset,
            int nativeOffset,
            string fileName,
            int lineNumber,
            int columnNumber,
            string memberName)
            : base(fileName, lineNumber, columnNumber)
        {
            _lineNumber = lineNumber;
            _columnNumber = columnNumber;
            _memberName = memberName;
            _fileName = fileName;
            _nativeOffset = nativeOffset;
            _ilOffset = ilOffset;
        }

        public override string ToString()
        {
            return $"{_memberName} at offset " +
                $"{_nativeOffset} in file: line: column {_fileName}" +
                $":{_lineNumber}:{_columnNumber}";
        }

        public override string GetFileName() => _fileName;

        public override int GetFileLineNumber() => _lineNumber;

        public override int GetFileColumnNumber() => _columnNumber;

        public override int GetNativeOffset() => _nativeOffset;

        public override int GetILOffset() => _ilOffset;

        public string MemberName => _memberName;
    }
}
#nullable restore
