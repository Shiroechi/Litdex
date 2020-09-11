using System;

using Litdex.Utilities.Number;
using Litdex.Utilities.Extension;

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

		private byte[] xBuf = new byte[4];
		private int xBufOff;

		private long byteCount;

		private uint H1, H2, H3, H4, H5;

		private uint[] X = new uint[80];
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
			X[xOff] = Pack.BE_To_UInt32(input, inOff);

			if (++xOff == 16)
			{
				ProcessBlock();
			}
		}

		private void ProcessLength(long bitLength)
		{
			if (xOff > 14)
			{
				ProcessBlock();
			}

			X[14] = (uint)((ulong)bitLength >> 32);
			X[15] = (uint)((ulong)bitLength);
		}

		public void ProcessBlock()
		{
			//
			// expand 16 word block into 80 word block.
			//
			for (int i = 16; i < 80; i++)
			{
				uint t = X[i - 3] ^ X[i - 8] ^ X[i - 14] ^ X[i - 16];
				X[i] = t << 1 | t >> 31;
			}

			//
			// set up working variables.
			//
			uint A = H1;
			uint B = H2;
			uint C = H3;
			uint D = H4;
			uint E = H5;

			//
			// round 1
			//
			int idx = 0;

			for (int j = 0; j < 4; j++)
			{
				// E = rotateLeft(A, 5) + F(B, C, D) + E + X[idx++] + Y1
				// B = rotateLeft(B, 30)
				E += (A << 5 | (A >> 27)) + F(B, C, D) + X[idx++] + Y1;
				B = B << 30 | (B >> 2);

				D += (E << 5 | (E >> 27)) + F(A, B, C) + X[idx++] + Y1;
				A = A << 30 | (A >> 2);

				C += (D << 5 | (D >> 27)) + F(E, A, B) + X[idx++] + Y1;
				E = E << 30 | (E >> 2);

				B += (C << 5 | (C >> 27)) + F(D, E, A) + X[idx++] + Y1;
				D = D << 30 | (D >> 2);

				A += (B << 5 | (B >> 27)) + F(C, D, E) + X[idx++] + Y1;
				C = C << 30 | (C >> 2);
			}

			//
			// round 2
			//
			for (int j = 0; j < 4; j++)
			{
				// E = rotateLeft(A, 5) + H(B, C, D) + E + X[idx++] + Y2
				// B = rotateLeft(B, 30)
				E += (A << 5 | (A >> 27)) + H(B, C, D) + X[idx++] + Y2;
				B = B << 30 | (B >> 2);

				D += (E << 5 | (E >> 27)) + H(A, B, C) + X[idx++] + Y2;
				A = A << 30 | (A >> 2);

				C += (D << 5 | (D >> 27)) + H(E, A, B) + X[idx++] + Y2;
				E = E << 30 | (E >> 2);

				B += (C << 5 | (C >> 27)) + H(D, E, A) + X[idx++] + Y2;
				D = D << 30 | (D >> 2);

				A += (B << 5 | (B >> 27)) + H(C, D, E) + X[idx++] + Y2;
				C = C << 30 | (C >> 2);
			}

			//
			// round 3
			//
			for (int j = 0; j < 4; j++)
			{
				// E = rotateLeft(A, 5) + G(B, C, D) + E + X[idx++] + Y3
				// B = rotateLeft(B, 30)
				E += (A << 5 | (A >> 27)) + G(B, C, D) + X[idx++] + Y3;
				B = B << 30 | (B >> 2);

				D += (E << 5 | (E >> 27)) + G(A, B, C) + X[idx++] + Y3;
				A = A << 30 | (A >> 2);

				C += (D << 5 | (D >> 27)) + G(E, A, B) + X[idx++] + Y3;
				E = E << 30 | (E >> 2);

				B += (C << 5 | (C >> 27)) + G(D, E, A) + X[idx++] + Y3;
				D = D << 30 | (D >> 2);

				A += (B << 5 | (B >> 27)) + G(C, D, E) + X[idx++] + Y3;
				C = C << 30 | (C >> 2);
			}

			//
			// round 4
			//
			for (int j = 0; j < 4; j++)
			{
				// E = rotateLeft(A, 5) + H(B, C, D) + E + X[idx++] + Y4
				// B = rotateLeft(B, 30)
				E += (A << 5 | (A >> 27)) + H(B, C, D) + X[idx++] + Y4;
				B = B << 30 | (B >> 2);

				D += (E << 5 | (E >> 27)) + H(A, B, C) + X[idx++] + Y4;
				A = A << 30 | (A >> 2);

				C += (D << 5 | (D >> 27)) + H(E, A, B) + X[idx++] + Y4;
				E = E << 30 | (E >> 2);

				B += (C << 5 | (C >> 27)) + H(D, E, A) + X[idx++] + Y4;
				D = D << 30 | (D >> 2);

				A += (B << 5 | (B >> 27)) + H(C, D, E) + X[idx++] + Y4;
				C = C << 30 | (C >> 2);
			}

			H1 += A;
			H2 += B;
			H3 += C;
			H4 += D;
			H5 += E;

			//
			// reset start of the buffer.
			//
			xOff = 0;
			Array.Clear(X, 0, 16);
		}

		private void Finish()
		{
			long bitLength = (byteCount << 3);

			//
			// add the pad bytes.
			//
			Update((byte)128);

			while (xBufOff != 0)
			{
				Update((byte)0);
			}

			ProcessLength(bitLength);
			ProcessBlock();
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
			xBuf[xBufOff++] = input;

			if (xBufOff == xBuf.Length)
			{
				ProcessWord(xBuf, 0);
				xBufOff = 0;
			}

			byteCount++;
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
			if (xBufOff != 0)
			{
				while (i < length)
				{
					xBuf[xBufOff++] = input[start_index + i++];
					if (xBufOff == 4)
					{
						ProcessWord(xBuf, 0);
						xBufOff = 0;
						break;
					}
				}
			}

			//
			// process whole words.
			//
			int limit = (((int)length - i) & ~3) + i;
			for (; i < limit; i += 4)
			{
				ProcessWord(input, (int)start_index + i);
			}

			//
			// load in the remainder.
			//
			while (i < length)
			{
				xBuf[xBufOff++] = input[(int)start_index + i++];
			}

			byteCount += length;
		}

		public int DoFinal(byte[] output)
		{
			return this.DoFinal(output, 0);
		}

		public int DoFinal(byte[] output, int start_index)
		{
			this.Finish();

			Pack.UInt32_To_BE(H1, output, start_index);
			Pack.UInt32_To_BE(H2, output, start_index + 4);
			Pack.UInt32_To_BE(H3, output, start_index + 8);
			Pack.UInt32_To_BE(H4, output, start_index + 12);
			Pack.UInt32_To_BE(H5, output, start_index + 16);

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