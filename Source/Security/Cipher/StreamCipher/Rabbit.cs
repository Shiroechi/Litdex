using System;

using Litdex.Utilities.Arrays;
using Litdex.Utilities.Extension;

namespace Litdex.Security.Cipher.StreamCipher
{
	/// <summary>
	/// High-speed stream cipher from eSTREAM.
	/// <list type="bullet">
	/// <item>
	///		http://tools.ietf.org/rfc/rfc4503.txt
	/// </item>
	/// </list>
	/// </summary>
	public class Rabbit : IStreamCipher
	{
		#region Member

		/// <summary>
		/// Key stream length.
		/// </summary>
		private readonly byte KeyStreamLength = 16;

		/// <summary>
		/// Constant counter.
		/// <see href="https://tools.ietf.org/html/rfc4503#section-2.5"/>
		/// </summary>
		private static readonly uint[] A = new uint[]
		{
			0x4D34D34D, 0xD34D34D3, 0x34D34D34, 0x4D34D34D,
			0xD34D34D3, 0x34D34D34, 0x4D34D34D, 0xD34D34D3
		};

		/// <summary>
		/// State
		/// </summary>
		private readonly int[] X = new int[8];

		/// <summary>
		/// Counter
		/// </summary>
		private readonly int[] C = new int[8];
		private byte b;
		private int KeyIndex = 0;
		private byte[] KeyStream = null;

		#endregion Member

		/// <summary>
		/// Costructor.
		/// </summary>
		public Rabbit()
		{
			this.b = 0;
		}

		/// <summary>
		/// Constructor.
		/// </summary>
		/// <param name="key">Secret Key.</param>
		/// <param name="iv">initialization Vector.</param>
		public Rabbit(byte[] key, byte[] iv) : this()
		{
			this.SetKey(key);
			this.SetIV(iv);
		}

		/// <summary>
		/// Destructor.
		/// </summary>
		~Rabbit()
		{
			this.Reset();
		}

		#region Private

		/// <summary>
		/// Create a key stream for first time.
		/// </summary>
		/// <returns>Array of bytes.</returns>
		private byte[] CreateKeyStream()
		{
			this.NextState();
			byte[] s = new byte[16];

			//unroll
			int x = this.X[6] ^ (int)((uint)this.X[3] >> 16) ^ this.X[1] << 16;
			s[0] = (byte)(int)((uint)x >> 24);
			s[1] = (byte)(x >> 16);
			s[2] = (byte)(x >> 8);
			s[3] = (byte)x;
			x = this.X[4] ^ (int)((uint)this.X[1] >> 16) ^ this.X[7] << 16;
			s[4] = (byte)(int)((uint)x >> 24);
			s[5] = (byte)(x >> 16);
			s[6] = (byte)(x >> 8);
			s[7] = (byte)x;
			x = this.X[2] ^ (int)((uint)this.X[7] >> 16) ^ this.X[5] << 16;
			s[8] = (byte)(int)((uint)x >> 24);
			s[9] = (byte)(x >> 16);
			s[10] = (byte)(x >> 8);
			s[11] = (byte)x;
			x = this.X[0] ^ (int)((uint)this.X[5] >> 16) ^ this.X[3] << 16;
			s[12] = (byte)(int)((uint)x >> 24);
			s[13] = (byte)(x >> 16);
			s[14] = (byte)(x >> 8);
			s[15] = (byte)x;
			return s;
		}

		/// <summary>
		/// Core of <see cref="Rabbit"/> algorithm.
		/// </summary>
		private void NextState()
		{
			/* counter update */
			for (int j = 0; j < 8; ++j)
			{
				long t = (this.C[j] & 0xFFFFFFFFL) + (A[j] & 0xFFFFFFFFL) + this.b;
				this.b = (byte)(int)((uint)t >> 32);
				this.C[j] = (int)(t & 0xFFFFFFFF);
			}
			/* next state function */
			int[] G = new int[8];
			for (int j = 0; j < 8; ++j)
			{
				// TODO: reduce this to use 32 bits only
				long t = this.X[j] + this.C[j] & 0xFFFFFFFFL;
				G[j] = (int)((t *= t) ^ (int)((uint)t >> 32));
			}
			/* unroll */
			this.X[0] = G[0] + this.RotateLeft(G[7], 16) + this.RotateLeft(G[6], 16);
			this.X[1] = G[1] + this.RotateLeft(G[0], 8) + G[7];
			this.X[2] = G[2] + this.RotateLeft(G[1], 16) + this.RotateLeft(G[0], 16);
			this.X[3] = G[3] + this.RotateLeft(G[2], 8) + G[1];
			this.X[4] = G[4] + this.RotateLeft(G[3], 16) + this.RotateLeft(G[2], 16);
			this.X[5] = G[5] + this.RotateLeft(G[4], 8) + G[3];
			this.X[6] = G[6] + this.RotateLeft(G[5], 16) + this.RotateLeft(G[4], 16);
			this.X[7] = G[7] + this.RotateLeft(G[6], 8) + G[5];
		}

		/// <summary>
		/// Encrypt message or Decrypt cipher text.
		/// Should be fed an array with a length that is
		/// a multiple of 16 for proper key sequencing.
		/// </summary>
		/// <param name="message">Message.</param>
		/// <returns></returns>
		private byte[] Crypt(byte[] message)
		{
			int index = 0;
			while (index < message.Length)
			{
				if (this.KeyStream == null || this.KeyIndex == this.KeyStreamLength)
				{
					this.KeyStream = this.CreateKeyStream();
					this.KeyIndex = 0;
				}

				for (; this.KeyIndex < this.KeyStreamLength && index < message.Length; ++this.KeyIndex)
				{
					message[index++] ^= this.KeyStream[this.KeyIndex];
				}
			}
			return message;
		}

		/// <summary>
		/// Clears all internal data. 
		/// You must set the key again to use this cypher.
		/// </summary>
		[Obsolete("Use Reset()")]
		private void Clear()
		{
			this.b = 0;
			this.KeyIndex = 0;
			this.KeyStream = null;
			Arrays.Fill(this.X, 0);
			Arrays.Fill(this.C, 0);
		}

		/// <summary>
		/// Set up a initialization vector.
		/// </summary>
		/// <param name="IV">An array of 4 short values.</param>
		private void SetupIV(short[] iv)
		{
			/* unroll */
			this.C[0] ^= iv[1] << 16 | iv[0] & 0xFFFF;
			this.C[1] ^= iv[3] << 16 | iv[1] & 0xFFFF;
			this.C[2] ^= iv[3] << 16 | iv[2] & 0xFFFF;
			this.C[3] ^= iv[2] << 16 | iv[0] & 0xFFFF;
			this.C[4] ^= iv[1] << 16 | iv[0] & 0xFFFF;
			this.C[5] ^= iv[3] << 16 | iv[1] & 0xFFFF;
			this.C[6] ^= iv[3] << 16 | iv[2] & 0xFFFF;
			this.C[7] ^= iv[2] << 16 | iv[0] & 0xFFFF;

			this.NextState();
			this.NextState();
			this.NextState();
			this.NextState();
		}
		
		/// <summary>
		/// Set up a key.
		/// </summary>
		/// <param name="key">An array of 4 short values.</param>
		private void SetupKey(short[] key)
		{
			/* unroll */
			this.X[0] = key[1] << 16 | key[0] & 0xFFFF;
			this.X[1] = key[6] << 16 | key[5] & 0xFFFF;
			this.X[2] = key[3] << 16 | key[2] & 0xFFFF;
			this.X[3] = key[0] << 16 | key[7] & 0xFFFF;
			this.X[4] = key[5] << 16 | key[4] & 0xFFFF;
			this.X[5] = key[2] << 16 | key[1] & 0xFFFF;
			this.X[6] = key[7] << 16 | key[6] & 0xFFFF;
			this.X[7] = key[4] << 16 | key[3] & 0xFFFF;
			/* unroll */
			this.C[0] = key[4] << 16 | key[5] & 0xFFFF;
			this.C[1] = key[1] << 16 | key[2] & 0xFFFF;
			this.C[2] = key[6] << 16 | key[7] & 0xFFFF;
			this.C[3] = key[3] << 16 | key[4] & 0xFFFF;
			this.C[4] = key[0] << 16 | key[1] & 0xFFFF;
			this.C[5] = key[5] << 16 | key[6] & 0xFFFF;
			this.C[6] = key[2] << 16 | key[3] & 0xFFFF;
			this.C[7] = key[7] << 16 | key[0] & 0xFFFF;
			this.NextState();
			this.NextState();
			this.NextState();
			this.NextState();
			/* unroll */
			this.C[0] ^= this.X[4];
			this.C[1] ^= this.X[5];
			this.C[2] ^= this.X[6];
			this.C[3] ^= this.X[7];
			this.C[4] ^= this.X[0];
			this.C[5] ^= this.X[1];
			this.C[6] ^= this.X[2];
			this.C[7] ^= this.X[3];
		}

		/// <summary>
		/// Circular Left Shift.
		/// </summary>
		/// <param name="value">Value to shift.</param>
		/// <param name="shift">Bit to shift.</param>
		/// <returns></returns>
		private int RotateLeft(int value, int shift)
		{
			return value << shift | (int)((uint)value >> 32 - shift);
		}

		#endregion Private

		#region Public

		/// <summary>
		/// The name of the algorithm this cipher implements.
		/// </summary>
		/// <returns></returns>
		public string AlgorithmName()
		{
			return "Rabbit";
		}

		/// <summary>
		/// Reset the cipher.
		/// </summary>
		public void Reset()
		{
			this.b = 0;
			this.KeyIndex = 0;
			this.KeyStream = null;
			Arrays.Fill(this.X, 0);
			Arrays.Fill(this.C, 0);
		}

		/// <summary>
		/// Set up Key.
		/// </summary>
		/// <param name="key">Key.</param>
		public void SetKey(byte[] key)
		{
			if (key.Length != 16)
			{
				throw new Exception("Key not 128 bit length.");
			}

			short[] sKey = new short[key.Length >> 1];
			for (int i = 0; i < sKey.Length; ++i)
			{
				sKey[i] = (short)((key[i << 1] << 8) | key[(2 << 1) + 1]);
			}
			this.SetupKey(sKey);
		}

		/// <summary>
		/// Set up IV (Initialization Vector).
		/// </summary>
		/// <param name="iv">IV.</param>
		public void SetIV(byte[] iv)
		{
			if (iv.Length != 8)
			{
				throw new Exception("IV not 64 bit length.");
			}

			short[] sIV = new short[iv.Length >> 1];
			for (int i = 0; i < sIV.Length; ++i)
			{
				sIV[i] = (short)((iv[i << 1] << 8) | iv[(2 << 1) + 1]);
			}
			this.SetupIV(sIV);
		}

		/// <summary>
		/// Encrypt data.
		/// </summary>
		/// <param name="data">Data to encrypt.</param>
		/// <returns></returns>
		public byte[] Encrypt(string data)
		{
			return this.Crypt(data.GetBytes());
		}

		/// <summary>
		/// Encrypt data.
		/// </summary>
		/// <param name="data">Data to encrypt.</param>
		/// <returns></returns>
		public byte[] Encrypt(byte[] data)
		{
			return this.Crypt(data);
		}

		/// <summary>
		/// Decrypt data.
		/// </summary>
		/// <param name="data">Data to decrypt.</param>
		/// <returns></returns>
		public byte[] Decrypt(string data)
		{
			return this.Crypt(data.GetBytes());
		}

		/// <summary>
		/// Decrypt data.
		/// </summary>
		/// <param name="data">Data to decrypt.</param>
		/// <returns></returns>
		public byte[] Decrypt(byte[] data)
		{
			return this.Crypt(data);
		}

		#endregion Public
	}
}
