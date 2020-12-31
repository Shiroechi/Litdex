using System;

using Litdex.Utilities.Extension;

//SHA3-224("")
//6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7
//SHA3-256("")
//a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a
//SHA3-384("")
//0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004
//SHA3-512("")
//a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26

namespace Litdex.Security.Hash
{
	/// <summary>
	/// Implementation of SHA-3 based on following KeccakNISTInterface.c from http://keccak.noekeon.org/
	/// </summary>
	/// <remarks>
	/// Following the naming conventions used in the C source code to enable easy review of the implementation.
	/// </remarks>
	public class SHA3 : Keccak
	{
		/// <summary>
		/// Constructor.
		/// </summary>
		/// <param name="bitLength">Hash value length.</param>
		public SHA3(int bitLength = 512) : base(CheckBitLength(bitLength))
		{

		}

		/// <summary>
		/// Destructor.
		/// </summary>
		~SHA3()
		{
			this.Reset();
		}

		#region Private

		private static int CheckBitLength(int bitLength)
		{
			switch (bitLength)
			{
				case 224:
				case 256:
				case 384:
				case 512:
					return bitLength;
				default:
					throw new ArgumentException(bitLength + " not supported for SHA-3", "bitLength");
			}
		}

		#endregion Private

		#region Public

		public override string AlgorithmName()
		{
			return "SHA3-" + this.fixedOutputLength;
		}

		public override int DoFinal(byte[] output)
		{
			return this.DoFinal(output, 0);
		}

		public override int DoFinal(byte[] output, int start_index)
		{
			this.AbsorbBits(0x02, 2);
			return base.DoFinal(output, start_index);
		}

		public override byte[] ComputeHash(byte[] input)
		{
			return this.ComputeHash(input, 0, input.Length);
		}

		public override byte[] ComputeHash(string input)
		{
			return this.ComputeHash(input.GetBytes());
		}

		public override byte[] ComputeHash(byte[] input, int start_index, int length)
		{
			byte[] result = new byte[this.GetHashLength()];
			this.Update(input, start_index, length);
			this.DoFinal(result, 0);
			return result;
		}

		public override IHash Clone()
		{
			return new SHA3();
		}

		#endregion Public 
	}
}
