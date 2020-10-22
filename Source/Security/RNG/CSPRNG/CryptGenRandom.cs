using System;
using System.Security.Cryptography;

namespace Litdex.Security.RNG.CSPRNG
{
	/// <summary>
	/// C# Windows built in CSPRNG
	/// </summary>
	public class CryptGenRandom : IRNG
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

		#region Private

		/// <summary>
		/// Generate next random number.
		/// </summary>
		/// <returns></returns>
		private ulong Next()
		{
			ulong result;
			using (var generator = new RNGCryptoServiceProvider())
			{
				var bytes = new byte[8];
				generator.GetNonZeroBytes(bytes);
				result = BitConverter.ToUInt64(bytes, 0);
			}
			return result;
		}

		#endregion Private

		#region Public

		/// <summary>
		/// The name of the algorithm this generator implements.
		/// </summary>
		/// <returns></returns>
		public string AlgorithmName()
		{
			return "CryptGenRandom";
		}

		/// <summary>
		/// Reset generator.
		/// do nothing.
		/// </summary>
		public void Reseed()
		{

		}

		/// <summary>
		/// Generate Boolean value from generator.
		/// </summary>
		/// <returns></returns>
		public bool NextBoolean()
		{
			return this.NextInt() % 2 == 0;
		}

		public virtual byte NextByte()
		{
			return this.GetBytes(1)[0];
		}

		public virtual byte NextByte(byte lower, byte upper)
		{
			if (lower >= upper)
			{
				throw new ArgumentException("The lower bound must not be greater than or equal to the upper bound.");
			}

			byte diff = (byte)(upper - lower + 1);
			return (byte)(lower + (this.NextByte() % diff));
		}

		/// <summary>
		/// Generate Integer value from generator.
		/// </summary>
		/// <returns></returns>
		public uint NextInt()
		{
			return (uint)this.Next();
		}

		public uint NextInt(uint lower, uint upper)
		{
			if (lower >= upper)
			{
				throw new ArgumentException("The lower bound must not be greater than or equal to the upper bound.");
			}

			uint diff = upper - lower + 1;
			return lower + (this.NextInt() % diff);
		}

		/// <summary>
		/// Generate Long value from generator.
		/// </summary>
		/// <returns></returns>
		public ulong NextLong()
		{
			return this.Next();
		}

		public ulong NextLong(ulong lower, ulong upper)
		{
			if (lower >= upper)
			{
				throw new ArgumentException("The lower bound must not be greater than or equal to the upper bound.");
			}

			ulong diff = upper - lower + 1;
			return lower + (this.NextLong() % diff);
		}

		/// <summary>
		/// Generate Double value from generator.
		/// </summary>
		/// <returns></returns>
		public double NextDouble()
		{
			return NextLong() * (1L << 53);
		}

		public double NextDouble(double lower, double upper)
		{
			if (lower >= upper)
			{
				throw new ArgumentException("The lower bound must not be greater than or equal to the upper bound.");
			}

			double diff = upper - lower + 1;
			return lower + (this.NextDouble() % diff);
		}

		/// <summary>
		/// Generate random byte[] value from generator.
		/// </summary>
		/// <param name="length">Length byte[].</param>
		public byte[] GetBytes(int length = 512)
		{
			byte[] result = new byte[length];
			using (var rngCsp = new RNGCryptoServiceProvider())
			{
				rngCsp.GetNonZeroBytes(result);
			}
			return result;
		}

		#endregion Public
	}
}