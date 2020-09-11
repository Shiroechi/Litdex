using System;
using System.Threading;

using Litdex.Security.RNG;
using Litdex.Security.RNG.CSPRNG;
using Litdex.Security.RNG.PRNG;
using Litdex.Utilities.Extension;

namespace Litdex.Test
{
	class RNGTest
	{
		public static IRNG[] GetList()
		{
			IRNG[] list = new IRNG[17];
			list[0] = new JSF32(1);
			list[1] = new JSF64(1);
			list[2] = new MiddleSquareWeylSequence(1);
			list[3] = new PermutedCongruentialGenerator(1);
			list[4] = new SplitMix64(1);
			list[5] = new Squares(1);
			list[6] = new WyRng(1);
			list[7] = new Xoroshiro128plus(1, 1);
			list[8] = new Xoroshiro128plusplus(1, 1);
			list[9] = new Xoroshiro128starstar(1, 1);
			list[10] = new Xoshiro256plus();
			list[11] = new Xoshiro256plusplus();
			list[12] = new Xoshiro256starstar();
			list[13] = new Xoshiro512plus();
			list[14] = new Xoshiro512plusplus();
			list[15] = new Xoshiro512starstar();
			list[16] = new CryptGenRandom();

			return list;
		}

		static void Main(string[] args)
		{
			Thread.Sleep(2000);
			Console.WriteLine("Starting...\n");

			//------------------------------------------------------------

			var list = RNGTest.GetList();

			for (int i = 0; i < list.Length; i++)
			{
				var bytes = new byte[16];
				byte length = 16;

				Console.WriteLine("Start " + list[i].AlgorithmName() + " test");

				Console.WriteLine(list[i].AlgorithmName());
				Console.WriteLine(list[i].NextBoolean());
				Console.WriteLine(list[i].NextInt());
				Console.WriteLine(list[i].NextInt(1, 1000000));
				Console.WriteLine(list[i].NextLong());
				Console.WriteLine(list[i].NextLong(1, 1000000));
				Console.WriteLine(list[i].NextDouble());
				Console.WriteLine(list[i].NextDouble(1, 1000000));

				list[i].Reseed();

				bytes = list[i].GetBytes(length);
				Console.WriteLine(bytes.EncodeBase16());

				Console.WriteLine("End of " + list[i].AlgorithmName() + " test \n\n");
			}

			//------------------------------------------------------------

			Console.WriteLine("\nProgram End.");
			Console.ReadKey();
			Console.ReadKey();
		}
	}
}
