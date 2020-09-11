using System;
using System.Threading;

using Litdex.Network;

namespace Litdex.Test
{
	class NetworkTest
	{
		static void Main(string[] args)
		{
			Thread.Sleep(2000);
			Console.WriteLine("Starting...\n");

			//------------------------------------------------------------

			Console.WriteLine(InternetConnection.InternetConnecion());
			Console.WriteLine(InternetConnection.DefaultGateway());
			Console.WriteLine(InternetConnection.LocalIP());
			Console.WriteLine(InternetConnection.PublicIP());
			Console.WriteLine(InternetConnection.CheckNetworkAdapter());

			//------------------------------------------------------------

			Console.WriteLine("\nProgram End.");
			Console.ReadKey();
			Console.ReadKey();
		}
	}
}
