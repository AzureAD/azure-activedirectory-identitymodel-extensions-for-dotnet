// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using System.Diagnostics;

#nullable enable

namespace Microsoft.IdentityModel.Tokens.Experimental
{
    internal class IdentityModelStackFrame : StackFrame
    {
        private string _memberName;
        private int _lineNumber;
        private int _columnNumber;
        private string _fileName;
        private int _nativeOffset;
        private int _ilOffset;

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

        public override string GetFileName()
        {
            return _fileName;
        }

        public override int GetFileLineNumber()
        {
            return _lineNumber;
        }

        public override int GetFileColumnNumber()
        {
            return _columnNumber;
        }

        public override int GetNativeOffset()
        {
            return _nativeOffset;
        }

        public override int GetILOffset()
        {
            return _ilOffset;
        }
    }
}
#nullable restore
