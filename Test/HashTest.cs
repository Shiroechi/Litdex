using System;
using System.Threading;

using Litdex.Security.Hash;
using Litdex.Utilities.Extension;

namespace Litdex.Test
{
	class HashTest
	{
		static void Main(string[] args)
		{
			Thread.Sleep(2000);
			Console.WriteLine("Starting...\n");

			//------------------------------------------------------------

			Console.WriteLine("Hash Test\n");

			IHash[] hash = new IHash[17];
			hash[0] = new Blake2b(512);
			hash[1] = new Blake2b(256);
			hash[2] = new SHA1();
			hash[3] = new SHA256();
			hash[4] = new SHA512();
			hash[5] = new Keccak(128);
			hash[6] = new Keccak(224);
			hash[7] = new Keccak(256);
			hash[8] = new Keccak(288);
			hash[9] = new Keccak(384);
			hash[10] = new Keccak(512);
			hash[11] = new SHA3(224);
			hash[12] = new SHA3(256);
			hash[13] = new SHA3(384);
			hash[14] = new SHA3(512);
			hash[15] = new SHAKE(128);
			hash[16] = new SHAKE(256);

			for (int i = 0; i < hash.Length; i++)
			{
				Console.WriteLine(hash[i].AlgorithmName());
				Console.WriteLine(hash[i].ComputeHash("").EncodeBase16());
				Console.WriteLine();
			}

			//------------------------------------------------------------

			Console.WriteLine("\nProgram End.");
			Console.ReadKey();
			Console.ReadKey();
		}
	}
}
