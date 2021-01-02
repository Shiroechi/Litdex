using System;

using Litdex.Utilities.Extension;

//Draft FIPS 180-2 implementation of SHA-256. 
//Note: As this is based on a draft this implementation is subject to change.

//			block word  digest
//	SHA-1   512    32    160
//	SHA-256 512    32    256
//	SHA-384 1024   64    384
//	SHA-512 1024   64    512

//SHA 256 ("")
//e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855

//SHA 256("hello world")
//B94D27B9934D3E08A52E52D7DA7DABFAC484EFE37A5380EE9088F7ACE2EFCDE9

namespace Litdex.Security.Hash
{
	/// <summary>
	/// Implementation of SHA-2 256 bit.
	/// </summary>
	public class SHA256 : IHash
	{
		#region Member

		private const int DigestLength = 32;
		private const int BYTE_LENGTH = 64;

		private readonly byte[] xBuf = new byte[4];
		private int xBufOff;

		private long byteCount;

		private uint H1, H2, H3, H4, H5, H6, H7, H8;
		private readonly uint[] X = new uint[64];
		private int xOff;

		#endregion Member

		/// <summary>
		/// Constructor.
		/// </summary>
		public SHA256()
		{
			this.InitializeHashValue();
		}

		/// <summary>
		/// Destructor.
		/// </summary>
		~SHA256()
		{
			this.Reset();
			this.K.Clear();
		}

		#region Private

		/// <summary>
		/// SHA-256 initial hash value.
		/// The first 32 bits of the fractional parts of
		/// the square roots of the first eight prime numbers.
		/// </summary>
		private void InitializeHashValue()
		{
			this.H1 = 0x6a09e667;
			this.H2 = 0xbb67ae85;
			this.H3 = 0x3c6ef372;
			this.H4 = 0xa54ff53a;
			this.H5 = 0x510e527f;
			this.H6 = 0x9b05688c;
			this.H7 = 0x1f83d9ab;
			this.H8 = 0x5be0cd19;
		}

		private void ProcessWord(byte[] input, int inOff)
		{
			this.X[this.xOff] = this.BE_To_UInt32(input, inOff);

			if (++this.xOff == 16)
			{
				this.ProcessBlock();
			}
		}

		private void ProcessLength(long bitLength)
		{
			if (this.xOff > 14)
			{
				this.ProcessBlock();
			}

			this.X[14] = (uint)((ulong)bitLength >> 32);
			this.X[15] = (uint)((ulong)bitLength);
		}

		public void ProcessBlock()
		{
			//
			// expand 16 word block into 64 word blocks.
			//
			for (int ti = 16; ti <= 63; ti++)
			{
				this.X[ti] = this.Theta1(this.X[ti - 2]) + this.X[ti - 7] + this.Theta0(this.X[ti - 15]) + this.X[ti - 16];
			}

			//
			// set up working variables.
			//
			uint a = this.H1;
			uint b = this.H2;
			uint c = this.H3;
			uint d = this.H4;
			uint e = this.H5;
			uint f = this.H6;
			uint g = this.H7;
			uint h = this.H8;

			int t = 0;
			for (int i = 0; i < 8; ++i)
			{
				// t = 8 * i
				h += this.Sum1Ch(e, f, g) + this.K[t] + this.X[t];
				d += h;
				h += this.Sum0Maj(a, b, c);
				++t;

				// t = 8 * i + 1
				g += this.Sum1Ch(d, e, f) + this.K[t] + this.X[t];
				c += g;
				g += this.Sum0Maj(h, a, b);
				++t;

				// t = 8 * i + 2
				f += this.Sum1Ch(c, d, e) + this.K[t] + this.X[t];
				b += f;
				f += this.Sum0Maj(g, h, a);
				++t;

				// t = 8 * i + 3
				e += this.Sum1Ch(b, c, d) + this.K[t] + this.X[t];
				a += e;
				e += this.Sum0Maj(f, g, h);
				++t;

				// t = 8 * i + 4
				d += this.Sum1Ch(a, b, c) + this.K[t] + this.X[t];
				h += d;
				d += this.Sum0Maj(e, f, g);
				++t;

				// t = 8 * i + 5
				c += this.Sum1Ch(h, a, b) + this.K[t] + this.X[t];
				g += c;
				c += this.Sum0Maj(d, e, f);
				++t;

				// t = 8 * i + 6
				b += this.Sum1Ch(g, h, a) + this.K[t] + this.X[t];
				f += b;
				b += this.Sum0Maj(c, d, e);
				++t;

				// t = 8 * i + 7
				a += this.Sum1Ch(f, g, h) + this.K[t] + this.X[t];
				e += a;
				a += this.Sum0Maj(b, c, d);
				++t;
			}

			this.H1 += a;
			this.H2 += b;
			this.H3 += c;
			this.H4 += d;
			this.H5 += e;
			this.H6 += f;
			this.H7 += g;
			this.H8 += h;

			//
			// reset the offset and clean out the word buffer.
			//
			this.xOff = 0;
			Array.Clear(this.X, 0, 16);
		}

		private void Finish()
		{
			long bitLength = (this.byteCount << 3);

			//
			// add the pad bytes.
			//
			this.Update(128);

			while (this.xBufOff != 0)
			{
				this.Update(0);
			}

			this.ProcessLength(bitLength);
			this.ProcessBlock();
		}

		private uint Sum1Ch(uint x, uint y, uint z)
		{
			return (((x >> 6) | (x << 26)) ^ ((x >> 11) | (x << 21)) ^ ((x >> 25) | (x << 7)))
				+ ((x & y) ^ ((~x) & z));
		}

		private uint Sum0Maj(uint x, uint y, uint z)
		{
			return (((x >> 2) | (x << 30)) ^ ((x >> 13) | (x << 19)) ^ ((x >> 22) | (x << 10)))
				+ ((x & y) ^ (x & z) ^ (y & z));
		}

		private uint Theta0(uint x)
		{
			return ((x >> 7) | (x << 25)) ^ ((x >> 18) | (x << 14)) ^ (x >> 3);
		}

		private uint Theta1(uint x)
		{
			return ((x >> 17) | (x << 15)) ^ ((x >> 19) | (x << 13)) ^ (x >> 10);
		}

		private uint BE_To_UInt32(byte[] bs, int off)
		{
			return (uint)bs[off] << 24
				| (uint)bs[off + 1] << 16
				| (uint)bs[off + 2] << 8
				| bs[off + 3];
		}

		private void UInt32_To_BE(uint n, byte[] bs, int off)
		{
			bs[off] = (byte)(n >> 24);
			bs[off + 1] = (byte)(n >> 16);
			bs[off + 2] = (byte)(n >> 8);
			bs[off + 3] = (byte)(n);
		}

		/// <summary>
		/// SHA-256 Constants.
		/// represent the first 32 bits 
		/// of the fractional parts of the 
		/// cube roots of the first sixty-four prime numbers.
		/// </summary>
		private readonly uint[] K =
		{
			0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
			0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
			0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
			0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
			0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
			0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
			0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
			0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
			0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
			0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
			0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
			0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
			0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
			0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
			0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
			0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
		};

		#endregion Private

		#region Public

		public string AlgorithmName()
		{
			return "SHA2-256";
		}

		public void Reset()
		{
			this.byteCount = 0;
			this.xBufOff = 0;
			Array.Clear(this.xBuf, 0, this.xBuf.Length);

			this.InitializeHashValue();

			this.xOff = 0;
			Array.Clear(this.X, 0, this.X.Length);
		}

		public int GetHashLength()
		{
			return DigestLength;
		}

		public int GetByteLength()
		{
			return BYTE_LENGTH;
		}

		public void Update(byte input)
		{
			this.xBuf[this.xBufOff++] = input;

			if (this.xBufOff == this.xBuf.Length)
			{
				this.ProcessWord(this.xBuf, 0);
				this.xBufOff = 0;
			}

			this.byteCount++;
		}

		public void Update(byte[] input)
		{
			this.Update(input, 0, input.Length);
		}

		public void Update(string input)
		{
			this.Update(input.GetBytes());
		}

		public void Update(byte[] input, int start_index, int length)
		{
			length = System.Math.Max(0, length);

			//
			// fill the current word
			//
			int i = 0;
			if (this.xBufOff != 0)
			{
				while (i < length)
				{
					this.xBuf[this.xBufOff++] = input[start_index + i++];
					if (this.xBufOff == 4)
					{
						this.ProcessWord(this.xBuf, 0);
						this.xBufOff = 0;
						break;
					}
				}
			}

			//
			// process whole words.
			//
			int limit = ((length - i) & ~3) + i;
			for (; i < limit; i += 4)
			{
				this.ProcessWord(input, start_index + i);
			}

			//
			// load in the remainder.
			//
			while (i < length)
			{
				this.xBuf[this.xBufOff++] = input[start_index + i++];
			}

			this.byteCount += length;
		}

		public int DoFinal(byte[] output)
		{
			return this.DoFinal(output, 0);
		}

		public int DoFinal(byte[] output, int start_index)
		{
			this.Finish();

			this.UInt32_To_BE(this.H1, output, start_index);
			this.UInt32_To_BE(this.H2, output, start_index + 4);
			this.UInt32_To_BE(this.H3, output, start_index + 8);
			this.UInt32_To_BE(this.H4, output, start_index + 12);
			this.UInt32_To_BE(this.H5, output, start_index + 16);
			this.UInt32_To_BE(this.H6, output, start_index + 20);
			this.UInt32_To_BE(this.H7, output, start_index + 24);
			this.UInt32_To_BE(this.H8, output, start_index + 28);

			this.Reset();

			return DigestLength;
		}

		public byte[] ComputeHash(byte[] input)
		{
			return this.ComputeHash(input, 0, input.Length);
		}

		public byte[] ComputeHash(string input)
		{
			return this.ComputeHash(input.GetBytes());
		}

		public byte[] ComputeHash(byte[] input, int start_index, int length)
		{
			byte[] result = new byte[DigestLength];
			this.Update(input, start_index, input.Length);
			this.DoFinal(result);
			return result;
		}

		public IHash Clone()
		{
			return new SHA256();
		}

		#endregion Pubblic
	}
}