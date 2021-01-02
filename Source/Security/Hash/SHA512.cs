using System;

using Litdex.Utilities.Extension;

//Draft FIPS 180-2 implementation of SHA-256. 
//Note: As this is based on a draft this implementation is subject to change.

//			block word  digest
//	SHA-1   512    32    160
//	SHA-256 512    32    256
//	SHA-384 1024   64    384
//	SHA-512 1024   64    512

//SHA 512 ("")
//cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e

//SHA 512("hello world")
//309ECC489C12D6EB4CC40F50C902F2B4D0ED77EE511A7C7A9BCD3CA86D4CD86F989DD35BC5FF499670DA34255B45B0CFD830E81F605DCF7DC5542E93AE9CD76F

namespace Litdex.Security.Hash
{
	/// <summary>
	/// Implementation of SHA-2 512 bit.
	/// </summary>
	public class SHA512 : IHash
	{
		#region Member

		private readonly int DigestLength = 64;
		private readonly int ByteLength = 128;

		private readonly byte[] xBuf = new byte[8];
		private int xBufOff;

		private long byteCount1;
		private long byteCount2;

		private ulong H1, H2, H3, H4, H5, H6, H7, H8;

		private readonly ulong[] W = new ulong[80];
		private int wOff;

		#endregion Member

		/// <summary>
		/// Constructor.
		/// </summary>
		public SHA512()
		{
			this.Reset();
		}

		/// <summary>
		/// Destructor.
		/// </summary>
		~SHA512()
		{
			this.Reset();
			this.K.Clear();
		}

		#region Private

		/// <summary>
		/// SHA-512 initial hash value.
		/// The first 64 bits of the fractional parts of
		/// the square roots of the first eight prime numbers.
		/// </summary>
		private void InitalizeHashValue()
		{
			this.H1 = 0x6a09e667f3bcc908;
			this.H2 = 0xbb67ae8584caa73b;
			this.H3 = 0x3c6ef372fe94f82b;
			this.H4 = 0xa54ff53a5f1d36f1;
			this.H5 = 0x510e527fade682d1;
			this.H6 = 0x9b05688c2b3e6c1f;
			this.H7 = 0x1f83d9abfb41bd6b;
			this.H8 = 0x5be0cd19137e2179;
		}

		private void Finish()
		{
			this.AdjustByteCounts();

			long lowBitLength = this.byteCount1 << 3;
			long hiBitLength = this.byteCount2;

			//
			// add the pad bytes.
			//
			this.Update(128);

			while (this.xBufOff != 0)
			{
				this.Update(0);
			}

			this.ProcessLength(lowBitLength, hiBitLength);

			this.ProcessBlock();
		}

		private void ProcessWord(byte[] input, int inOff)
		{
			this.W[this.wOff] = this.BE_To_UInt64(input, inOff);

			if (++this.wOff == 16)
			{
				this.ProcessBlock();
			}
		}

		/// <summary>
		/// Adjust the byte counts so that byteCount2 represents the
		/// upper long (less 3 bits) word of the byte count.
		/// </summary>
		private void AdjustByteCounts()
		{
			if (this.byteCount1 > 0x1fffffffffffffffL)
			{
				this.byteCount2 += (long)((ulong)this.byteCount1 >> 61);
				this.byteCount1 &= 0x1fffffffffffffffL;
			}
		}

		private void ProcessLength(long lowW, long hiW)
		{
			if (this.wOff > 14)
			{
				this.ProcessBlock();
			}

			this.W[14] = (ulong)hiW;
			this.W[15] = (ulong)lowW;
		}

		private void ProcessBlock()
		{
			this.AdjustByteCounts();

			//
			// expand 16 word block into 80 word blocks.
			//
			for (int ti = 16; ti <= 79; ++ti)
			{
				this.W[ti] = this.Sigma1(this.W[ti - 2]) + this.W[ti - 7] + this.Sigma0(this.W[ti - 15]) + this.W[ti - 16];
			}

			//
			// set up working variables.
			//
			ulong a = this.H1;
			ulong b = this.H2;
			ulong c = this.H3;
			ulong d = this.H4;
			ulong e = this.H5;
			ulong f = this.H6;
			ulong g = this.H7;
			ulong h = this.H8;

			int t = 0;
			for (int i = 0; i < 10; i++)
			{
				// t = 8 * i
				h += this.Sum1(e) + this.Ch(e, f, g) + this.K[t] + this.W[t++];
				d += h;
				h += this.Sum0(a) + this.Maj(a, b, c);

				// t = 8 * i + 1
				g += this.Sum1(d) + this.Ch(d, e, f) + this.K[t] + this.W[t++];
				c += g;
				g += this.Sum0(h) + this.Maj(h, a, b);

				// t = 8 * i + 2
				f += this.Sum1(c) + this.Ch(c, d, e) + this.K[t] + this.W[t++];
				b += f;
				f += this.Sum0(g) + this.Maj(g, h, a);

				// t = 8 * i + 3
				e += this.Sum1(b) + this.Ch(b, c, d) + this.K[t] + this.W[t++];
				a += e;
				e += this.Sum0(f) + this.Maj(f, g, h);

				// t = 8 * i + 4
				d += this.Sum1(a) + this.Ch(a, b, c) + this.K[t] + this.W[t++];
				h += d;
				d += this.Sum0(e) + this.Maj(e, f, g);

				// t = 8 * i + 5
				c += this.Sum1(h) + this.Ch(h, a, b) + this.K[t] + this.W[t++];
				g += c;
				c += this.Sum0(d) + this.Maj(d, e, f);

				// t = 8 * i + 6
				b += this.Sum1(g) + this.Ch(g, h, a) + this.K[t] + this.W[t++];
				f += b;
				b += this.Sum0(c) + this.Maj(c, d, e);

				// t = 8 * i + 7
				a += this.Sum1(f) + this.Ch(f, g, h) + this.K[t] + this.W[t++];
				e += a;
				a += this.Sum0(b) + this.Maj(b, c, d);
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
			this.wOff = 0;
			Array.Clear(this.W, 0, 16);
		}

		private ulong BE_To_UInt64(byte[] bs, int off)
		{
			uint hi = this.BE_To_UInt32(bs, off);
			uint lo = this.BE_To_UInt32(bs, off + 4);
			return ((ulong)hi << 32) | lo;
		}

		private uint BE_To_UInt32(byte[] bs)
		{
			return (uint)bs[0] << 24 | (uint)bs[1] << 16 | (uint)bs[2] << 8 | bs[3];
		}

		private uint BE_To_UInt32(byte[] bs, int off)
		{
			return (uint)bs[off] << 24 | (uint)bs[off + 1] << 16 | (uint)bs[off + 2] << 8 | bs[off + 3];
		}

		/// <summary>
		/// SHA-384 and SHA-512 functions (as for SHA-256 but for longs)
		/// </summary>
		/// <param name="x"></param>
		/// <param name="y"></param>
		/// <param name="z"></param>
		/// <returns></returns>
		private ulong Ch(ulong x, ulong y, ulong z)
		{
			return (x & y) ^ (~x & z);
		}

		private ulong Maj(ulong x, ulong y, ulong z)
		{
			return (x & y) ^ (x & z) ^ (y & z);
		}

		private ulong Sum0(ulong x)
		{
			return ((x << 36) | (x >> 28)) ^ ((x << 30) | (x >> 34)) ^ ((x << 25) | (x >> 39));
		}

		private ulong Sum1(ulong x)
		{
			return ((x << 50) | (x >> 14)) ^ ((x << 46) | (x >> 18)) ^ ((x << 23) | (x >> 41));
		}

		private ulong Sigma0(ulong x)
		{
			return ((x << 63) | (x >> 1)) ^ ((x << 56) | (x >> 8)) ^ (x >> 7);
		}

		private ulong Sigma1(ulong x)
		{
			return ((x << 45) | (x >> 19)) ^ ((x << 3) | (x >> 61)) ^ (x >> 6);
		}

		private void UInt64_To_BE(ulong n, byte[] bs, int off)
		{
			this.UInt32_To_BE((uint)(n >> 32), bs, off);
			this.UInt32_To_BE((uint)(n), bs, off + 4);
		}

		private void UInt32_To_BE(uint n, byte[] bs, int off)
		{
			bs[off] = (byte)(n >> 24);
			bs[off + 1] = (byte)(n >> 16);
			bs[off + 2] = (byte)(n >> 8);
			bs[off + 3] = (byte)(n);
		}

		/// <summary>
		/// SHA-384 and SHA-512 Constants.
		/// represent the first 64 bits of the fractional parts of the
		/// cube roots of the first sixty-four prime numbers.
		/// </summary>
		private readonly ulong[] K =
		{
			0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
			0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
			0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
			0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
			0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
			0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
			0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
			0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
			0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
			0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
			0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
			0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
			0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
			0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
			0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
			0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
			0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
			0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
			0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
			0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
		};

		#endregion Private

		#region Public

		public string AlgorithmName()
		{
			return "SHA2-512";
		}

		public void Reset()
		{
			this.byteCount1 = 0;
			this.byteCount2 = 0;

			this.xBufOff = 0;
			for (int i = 0; i < this.xBuf.Length; i++)
			{
				this.xBuf[i] = 0;
			}

			this.wOff = 0;
			Array.Clear(this.W, 0, this.W.Length);

			this.InitalizeHashValue();
		}

		public int GetHashLength()
		{
			return this.DigestLength;
		}

		public int GetByteLength()
		{
			return this.ByteLength;
		}

		public void Update(byte input)
		{
			this.xBuf[this.xBufOff++] = input;

			if (this.xBufOff == this.xBuf.Length)
			{
				this.ProcessWord(this.xBuf, 0);
				this.xBufOff = 0;
			}

			this.byteCount1++;
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
			//
			// fill the current word
			//
			while ((this.xBufOff != 0) && (length > 0))
			{
				this.Update(input[start_index]);

				start_index++;
				length--;
			}

			//
			// process whole words.
			//
			while (length > this.xBuf.Length)
			{
				this.ProcessWord(input, start_index);

				start_index += this.xBuf.Length;
				length -= this.xBuf.Length;
				this.byteCount1 += this.xBuf.Length;
			}

			//
			// load in the remainder.
			//
			while (length > 0)
			{
				this.Update(input[start_index]);

				start_index++;
				length--;
			}
		}

		public int DoFinal(byte[] output)
		{
			return this.DoFinal(output, 0);
		}

		public int DoFinal(byte[] output, int start_index)
		{
			this.Finish();

			this.UInt64_To_BE(this.H1, output, start_index);
			this.UInt64_To_BE(this.H2, output, start_index + 8);
			this.UInt64_To_BE(this.H3, output, start_index + 16);
			this.UInt64_To_BE(this.H4, output, start_index + 24);
			this.UInt64_To_BE(this.H5, output, start_index + 32);
			this.UInt64_To_BE(this.H6, output, start_index + 40);
			this.UInt64_To_BE(this.H7, output, start_index + 48);
			this.UInt64_To_BE(this.H8, output, start_index + 56);

			this.Reset();

			return this.DigestLength;
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
			byte[] result = new byte[this.DigestLength];
			this.Update(input, start_index, length);
			this.DoFinal(result, 0);
			return result;
		}

		public IHash Clone()
		{
			return new SHA512();
		}

		#endregion Public
	}
}
