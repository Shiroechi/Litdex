using System;

using Litdex.Utilities.Extension;
using Litdex.Utilities.Number;

//SHA1("")
//da39a3ee5e6b4b0d3255bfef95601890afd80709

//HMAC_SHA1("", "")
//FBDB1D1B18AA6C08324B7D64B71FB76370690E1D

namespace Litdex.Security.Hash
{
	/// <summary>
	/// Implementation of SHA-1 as outlined in "Handbook of Applied Cryptography", pages 346 - 349.
	/// 
	/// It is interesting to ponder why the, apart from the extra IV, the other difference here from MD5
	/// is the "endianness" of the word processing!
	/// </summary>
	public class SHA1 : IHash
	{
		#region Member

		private const int DigestLength = 20;
		private const int BYTE_LENGTH = 64;

		private readonly byte[] xBuf = new byte[4];
		private int xBufOff;

		private long byteCount;

		private uint H1, H2, H3, H4, H5;

		private readonly uint[] X = new uint[80];
		private int xOff;

		//
		// Additive constants
		//
		private const uint Y1 = 0x5A827999;
		private const uint Y2 = 0x6ED9EBA1;
		private const uint Y3 = 0x8F1BBCDC;
		private const uint Y4 = 0xCA62C1D6;

		#endregion Member

		/// <summary>
		/// Default constructor.
		/// </summary>
		public SHA1()
		{
			this.Reset();
		}

		/// <summary>
		/// Destructor.
		/// </summary>
		~SHA1()
		{
			this.Reset();
		}

		#region Private

		private void ProcessWord(byte[] input, int inOff)
		{
			this.X[this.xOff] = Pack.BE_To_UInt32(input, inOff);

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
			// expand 16 word block into 80 word block.
			//
			for (int i = 16; i < 80; i++)
			{
				uint t = this.X[i - 3] ^ this.X[i - 8] ^ this.X[i - 14] ^ this.X[i - 16];
				this.X[i] = t << 1 | t >> 31;
			}

			//
			// set up working variables.
			//
			uint A = this.H1;
			uint B = this.H2;
			uint C = this.H3;
			uint D = this.H4;
			uint E = this.H5;

			//
			// round 1
			//
			int idx = 0;

			for (int j = 0; j < 4; j++)
			{
				// E = rotateLeft(A, 5) + F(B, C, D) + E + X[idx++] + Y1
				// B = rotateLeft(B, 30)
				E += (A << 5 | (A >> 27)) + this.F(B, C, D) + this.X[idx++] + Y1;
				B = B << 30 | (B >> 2);

				D += (E << 5 | (E >> 27)) + this.F(A, B, C) + this.X[idx++] + Y1;
				A = A << 30 | (A >> 2);

				C += (D << 5 | (D >> 27)) + this.F(E, A, B) + this.X[idx++] + Y1;
				E = E << 30 | (E >> 2);

				B += (C << 5 | (C >> 27)) + this.F(D, E, A) + this.X[idx++] + Y1;
				D = D << 30 | (D >> 2);

				A += (B << 5 | (B >> 27)) + this.F(C, D, E) + this.X[idx++] + Y1;
				C = C << 30 | (C >> 2);
			}

			//
			// round 2
			//
			for (int j = 0; j < 4; j++)
			{
				// E = rotateLeft(A, 5) + H(B, C, D) + E + X[idx++] + Y2
				// B = rotateLeft(B, 30)
				E += (A << 5 | (A >> 27)) + this.H(B, C, D) + this.X[idx++] + Y2;
				B = B << 30 | (B >> 2);

				D += (E << 5 | (E >> 27)) + this.H(A, B, C) + this.X[idx++] + Y2;
				A = A << 30 | (A >> 2);

				C += (D << 5 | (D >> 27)) + this.H(E, A, B) + this.X[idx++] + Y2;
				E = E << 30 | (E >> 2);

				B += (C << 5 | (C >> 27)) + this.H(D, E, A) + this.X[idx++] + Y2;
				D = D << 30 | (D >> 2);

				A += (B << 5 | (B >> 27)) + this.H(C, D, E) + this.X[idx++] + Y2;
				C = C << 30 | (C >> 2);
			}

			//
			// round 3
			//
			for (int j = 0; j < 4; j++)
			{
				// E = rotateLeft(A, 5) + G(B, C, D) + E + X[idx++] + Y3
				// B = rotateLeft(B, 30)
				E += (A << 5 | (A >> 27)) + this.G(B, C, D) + this.X[idx++] + Y3;
				B = B << 30 | (B >> 2);

				D += (E << 5 | (E >> 27)) + this.G(A, B, C) + this.X[idx++] + Y3;
				A = A << 30 | (A >> 2);

				C += (D << 5 | (D >> 27)) + this.G(E, A, B) + this.X[idx++] + Y3;
				E = E << 30 | (E >> 2);

				B += (C << 5 | (C >> 27)) + this.G(D, E, A) + this.X[idx++] + Y3;
				D = D << 30 | (D >> 2);

				A += (B << 5 | (B >> 27)) + this.G(C, D, E) + this.X[idx++] + Y3;
				C = C << 30 | (C >> 2);
			}

			//
			// round 4
			//
			for (int j = 0; j < 4; j++)
			{
				// E = rotateLeft(A, 5) + H(B, C, D) + E + X[idx++] + Y4
				// B = rotateLeft(B, 30)
				E += (A << 5 | (A >> 27)) + this.H(B, C, D) + this.X[idx++] + Y4;
				B = B << 30 | (B >> 2);

				D += (E << 5 | (E >> 27)) + this.H(A, B, C) + this.X[idx++] + Y4;
				A = A << 30 | (A >> 2);

				C += (D << 5 | (D >> 27)) + this.H(E, A, B) + this.X[idx++] + Y4;
				E = E << 30 | (E >> 2);

				B += (C << 5 | (C >> 27)) + this.H(D, E, A) + this.X[idx++] + Y4;
				D = D << 30 | (D >> 2);

				A += (B << 5 | (B >> 27)) + this.H(C, D, E) + this.X[idx++] + Y4;
				C = C << 30 | (C >> 2);
			}

			this.H1 += A;
			this.H2 += B;
			this.H3 += C;
			this.H4 += D;
			this.H5 += E;

			//
			// reset start of the buffer.
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

		private uint F(uint u, uint v, uint w)
		{
			return (u & v) | (~u & w);
		}

		private uint H(uint u, uint v, uint w)
		{
			return u ^ v ^ w;
		}

		private uint G(uint u, uint v, uint w)
		{
			return (u & v) | (u & w) | (v & w);
		}

		#endregion Private

		#region Public

		public string AlgorithmName()
		{
			return "SHA-1";
		}

		public void Reset()
		{
			this.byteCount = 0;
			this.xBufOff = 0;
			Array.Clear(this.xBuf, 0, this.xBuf.Length);

			this.H1 = 0x67452301;
			this.H2 = 0xefcdab89;
			this.H3 = 0x98badcfe;
			this.H4 = 0x10325476;
			this.H5 = 0xc3d2e1f0;

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

			Pack.UInt32_To_BE(this.H1, output, start_index);
			Pack.UInt32_To_BE(this.H2, output, start_index + 4);
			Pack.UInt32_To_BE(this.H3, output, start_index + 8);
			Pack.UInt32_To_BE(this.H4, output, start_index + 12);
			Pack.UInt32_To_BE(this.H5, output, start_index + 16);

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
			this.Update(input, start_index, length);
			this.DoFinal(result);
			return result;
		}

		public IHash Clone()
		{
			return new SHA1();
		}

		#endregion Public	
	}
}