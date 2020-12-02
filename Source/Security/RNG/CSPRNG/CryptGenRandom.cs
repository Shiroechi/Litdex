using System;
using System.Security.Cryptography;

namespace Litdex.Security.RNG.CSPRNG
{
	/// <summary>
	/// C# Windows built in CSPRNG
	/// </summary>
	public class CryptGenRandom : Random
	{
		#region Deprecated

		/// <summary>
		/// Get Integer value from generator.
		/// </summary>
		/// <returns>INT value.</returns>
		[Obsolete]
		public static uint GetInt()
		{
			byte[] result = new byte[4];
			using (var rngCsp = new RNGCryptoServiceProvider())
			{
				rngCsp.GetNonZeroBytes(result);
				rngCsp.Dispose();
			}
			return BitConverter.ToUInt32(result, 0);
		}

		/// <summary>
		/// Get Long value from generator.
		/// </summary>
		/// <returns></returns>
		[Obsolete]
		public static ulong GetLong()
		{
			ulong result;
			using (var a = new RNGCryptoServiceProvider())
			{
				var b = new byte[8];
				a.GetNonZeroBytes(b);
				result = BitConverter.ToUInt64(b, 0);
			}
			return result;
		}

		/// <summary>
		/// Get byte[] from generator.
		/// </summary>
		/// <param name="size">Output size. (in byte)</param>
		/// <returns>byte[]</returns>
		[Obsolete]
		public static byte[] GetByte(int size = 512)
		{
			byte[] result = new byte[size];
			using (var rngCsp = new RNGCryptoServiceProvider())
			{
				rngCsp.GetNonZeroBytes(result);
			}
			return result;
		}

		/// <summary>
		/// Get CSPRNG string.
		/// </summary>
		/// <param name="size">Output size. (in char)</param>
		/// <returns>string</returns>
		[Obsolete]
		public static string GetString(int size = 512)
		{
			byte[] result = new byte[size];
			using (var rngCsp = new RNGCryptoServiceProvider())
			{
				rngCsp.GetNonZeroBytes(result);
				rngCsp.Dispose();
			}

			string data = "";
			for (int i = 0; i < result.Length; i++)
			{
				data += Convert.ToChar(result[i]);
			}
			return data;
		}

		#endregion Deprecated

		#region Constructor

		/// <summary>
		/// Default constructor.
		/// </summary>
		public CryptGenRandom()
		{

		}

		#endregion Constructor

		#region Public

		/// <inheritdoc/>
		public override string AlgorithmName()
		{
			return "CryptGenRandom";
		}

		/// <inheritdoc/>
		public override void Reseed()
		{

		}

		/// <inheritdoc/>
		public override bool NextBoolean()
		{
			return this.NextBytes(1)[0] >> 7 == 0;
		}

		/// <inheritdoc/>
		public override byte[] NextBytes(int length = 512)
		{
			var result = new byte[length];
			using (var rngCsp = new RNGCryptoServiceProvider())
			{
				rngCsp.GetNonZeroBytes(result);
			}
			return result;
		}

		/// <inheritdoc/>
		public override uint NextInt()
		{
			var bytes = this.NextBytes(4);
			uint a = bytes[0];
			uint b = bytes[1];
			uint c = bytes[2];
			uint d = bytes[3];
			return (a << 24) | (b << 16) | (c << 8) | d;
		}

		/// <inheritdoc/>
		public override ulong NextLong()
		{
			var bytes = this.NextBytes(8);
			uint a = bytes[0];
			uint b = bytes[1];
			uint c = bytes[2];
			uint d = bytes[3];
			uint e = bytes[4];
			uint f = bytes[5];
			uint g = bytes[6];
			uint h = bytes[7];
			return (a << 56) | (b << 48) | (c << 40) | (d << 32) | 
				(e << 24) | (f << 16) | (g << 8) | h;
		}

		#endregion Public
	}
}