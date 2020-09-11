using System;

using Litdex.Utilities.Extension;

//SHAKE128("", 256)
//7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26
//SHAKE256("", 512)
//46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762fd75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be

namespace Litdex.Security.Hash
{
	/// <summary>
	/// Implementation of SHAKE based on following KeccakNISTInterface.c from http://keccak.noekeon.org/
	/// </summary>
	/// <remarks>
	/// Following the naming conventions used in the C source code to enable easy review of the implementation.
	/// </remarks>
	public class SHAKE : Keccak, IHashExtend
    {
		/// <summary>
		/// Constructor.
		/// </summary>
		/// <param name="bitLength">Output byte.</param>
        public SHAKE(int bitLength = 256) : base(CheckBitLength(bitLength))
        {

        }

		/// <summary>
		/// Destructor.
		/// </summary>
		~SHAKE()
		{
			this.Reset();
		}

		#region Private

		private static int CheckBitLength(int bitLength)
		{
			switch (bitLength)
			{
				case 128:
				case 256:
					return bitLength;
				default:
					throw new ArgumentException(bitLength + " not supported for SHAKE.", "bitLength");
			}
		}

		#endregion Private

		#region Protected
		
		[Obsolete]
		protected virtual int DoOutput(byte[] output, int outOff, int outLen)
		{
			if (!this.squeezing)
			{
				this.AbsorbBits(0x0F, 4);
			}

			this.Squeeze(output, outOff, (long)outLen << 3);

			return outLen;
		}

		#endregion Protected

		#region Public

		public override string AlgorithmName()
		{
			return "SHAKE-" + fixedOutputLength;
		}

		public override int DoFinal(byte[] output)
		{
			return this.DoFinal(output, 0);
		}

		public override int DoFinal(byte[] output, int start_index)
		{
			return this.DoFinal(output, start_index, this.GetHashLength());
		}

		public virtual int DoFinal(byte[] output, int start_index, int length)
		{
			if (!this.squeezing)
			{
				this.AbsorbBits(0x0F, 4);
			}

			this.Squeeze(output, start_index, (long)length << 3);

			this.Reset();

			return length;
		}

		public override byte[] ComputeHash(byte[] input)
		{
			return this.ComputeHash(input, 0, this.GetHashLength());
		}

		public override byte[] ComputeHash(string input)
		{
			return this.ComputeHash(input.GetBytes());
		}

		public override byte[] ComputeHash(byte[] input, int start_index, int length)
		{
			byte[] result = new byte[length];
			this.Update(input);
			this.DoFinal(result, 0, length);
			return result;
		}

		public override IHash Clone()
		{
			return new SHAKE();
		}

		#endregion Public
	}
}
