using System;
using System.Collections.Generic;
using System.Linq;
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

		/// <inheritdoc/>
		public string AlgorithmName()
		{
			return "CryptGenRandom";
		}

		/// <inheritdoc/>
		public void Reseed()
		{

		}

		/// <inheritdoc/>
		public bool NextBoolean()
		{
			return this.NextInt() % 2 == 0;
		}

		/// <inheritdoc/>
		public virtual byte NextByte()
		{
			return this.GetBytes(1)[0];
		}

		/// <inheritdoc/>
		public virtual byte NextByte(byte lower, byte upper)
		{
			if (lower >= upper)
			{
				throw new ArgumentException("The lower bound must not be greater than or equal to the upper bound.");
			}

			var diff = (byte)(upper - lower + 1);
			return (byte)(lower + (this.NextByte() % diff));
		}

		/// <inheritdoc/>
		public byte[] NextBytes(int length = 512)
		{
			var result = new byte[length];
			using (var rngCsp = new RNGCryptoServiceProvider())
			{
				rngCsp.GetNonZeroBytes(result);
			}
			return result;
		}

		/// <inheritdoc/>
		public uint NextInt()
		{
			return (uint)this.Next();
		}

		/// <inheritdoc/>
		public uint NextInt(uint lower, uint upper)
		{
			if (lower >= upper)
			{
				throw new ArgumentException("The lower bound must not be greater than or equal to the upper bound.");
			}

			var diff = upper - lower + 1;
			return lower + (this.NextInt() % diff);
		}

		/// <inheritdoc/>
		public ulong NextLong()
		{
			return this.Next();
		}

		/// <inheritdoc/>
		public ulong NextLong(ulong lower, ulong upper)
		{
			if (lower >= upper)
			{
				throw new ArgumentException("The lower bound must not be greater than or equal to the upper bound.");
			}

			var diff = upper - lower + 1;
			return lower + (this.NextLong() % diff);
		}

		/// <inheritdoc/>
		public double NextDouble()
		{
			return NextLong() * (1L << 53);
		}

		/// <inheritdoc/>
		public double NextDouble(double lower, double upper)
		{
			if (lower >= upper)
			{
				throw new ArgumentException("The lower bound must not be greater than or equal to the upper bound.");
			}

			var diff = upper - lower + 1;
			return lower + (this.NextDouble() % diff);
		}

		/// <inheritdoc/>
		public virtual T Choice<T>(T[] items)
		{
			if (items.Length > int.MaxValue)
			{
				throw new ArgumentOutOfRangeException(nameof(items), $"The items length or size can't be greater than int.MaxValue or { int.MaxValue }.");
			}

			return items[(int)this.NextInt(0, (uint)(items.Length - 1))];
		}

		/// <inheritdoc/>
		public virtual T[] Choice<T>(T[] items, int select)
		{
			if (select < 0)
			{
				throw new ArgumentOutOfRangeException(nameof(select), $"The number of elements to be retrieved is negative or less than 1.");
			}

			if (select > items.Length)
			{
				throw new ArgumentOutOfRangeException(nameof(select), $"The number of elements to be retrieved exceeds the items size.");
			}

			var selected = new List<T>();

			while (selected.Count < select)
			{
				var index = this.NextInt(0, (uint)(items.Length - 1));

				if (selected.Contains(items[index]) == false)
				{
					selected.Add(items[index]);
				}
			}

			return selected.ToArray();
		}

		/// <inheritdoc/>
		public virtual T Choice<T>(IList<T> items)
		{
			return this.Choice(items.ToArray());
		}

		/// <inheritdoc/>
		public virtual T[] Choice<T>(IList<T> items, int select)
		{
			return this.Choice(items.ToArray(), select);
		}

		#endregion Public
	}
}