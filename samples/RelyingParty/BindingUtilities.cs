//------------------------------------------------------------------------------
//
// Copyright (c) Microsoft Corporation.
// All rights reserved.
//
// This code is licensed under the MIT License.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files(the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and / or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions :
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
//
//------------------------------------------------------------------------------

using System;
using System.ServiceModel;
using System.ServiceModel.Channels;
using System.ServiceModel.Dispatcher;

namespace WcfUtilities
{
    public static class BindingUtilities
    {
        public static void DisplayBindingInfoToConsole(ServiceHost serviceHost, string message)
        {
            Console.WriteLine(message);
            Console.WriteLine("====================");
            DisplayBindingInfoToConsole(serviceHost);
            Console.WriteLine("");
        }

        public static void DisplayBindingInfoToConsole(ServiceHost serviceHost)
        {

            foreach(var item in serviceHost.ChannelDispatchers)
            {
                if (item is ChannelDispatcher channelDispatcher)
                {
                    for (int j = 0; j < channelDispatcher.Endpoints.Count; j++)
                    {
                        EndpointDispatcher endpointDispatcher = channelDispatcher.Endpoints[j];
                        Console.WriteLine("Listening on " + endpointDispatcher.EndpointAddress + "...");
                    }
                }
            }
        }

        public static Binding SetMaxTimeout(Binding binding, TimeSpan timeSpan)
        {
            binding.CloseTimeout = timeSpan;
            binding.OpenTimeout = timeSpan;
            binding.ReceiveTimeout = timeSpan;
            binding.SendTimeout = timeSpan;

            return binding;
        }

        public static Binding SetMaxTimeout(Binding binding)
        {
            return SetMaxTimeout(binding, TimeSpan.MaxValue);
        }
    }
}
