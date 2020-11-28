﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;

using Litdex.Security.RNG;
using Litdex.Utilities.Extension;

namespace Litdex.Source.Security.RNG.CSPRNG
{
	/// <summary>
	/// Australian National University Quantum Random Number Generator. 
	/// <para>
	/// All number generated by measuring the quantum fluctuations of the vacuum.
	/// </para>
	/// <para>
	/// website: https://qrng.anu.edu.au/
	/// </para>
	/// </summary>
	public class ANUQRNG : IRNG
	{
		#region Member

		private readonly string _BaseUrl;
		private readonly ushort _Max = 1024;
		private readonly ANUType _Type;

		#endregion Member

		#region Constrcutor & Destructor

		/// <summary>
		/// Create RNG instance.
		/// </summary>
		/// <param name="type">Data type to get.</param>
		public ANUQRNG(ANUType type = ANUType.HEX16)
		{
			this._BaseUrl = "https://qrng.anu.edu.au/API/jsonI.php?";
			this._Type = type;
		}

		~ANUQRNG()
		{

		}

		#endregion Constrcutor & Destructor

		#region Protected

		/// <summary>
		/// Create API url for generate JSON data from ANU.
		/// </summary>
		/// <param name="size">Length of string (HEX16 type only)</param>
		/// <param name="length">How many record to get.</param>
		/// <returns></returns>
		protected string UrlBuilder(ushort length = 1, ushort size = 1024)
		{
			return this._BaseUrl + 
				"length=" + length +
				"&type=" + this._Type.ToString().ToLower() +
				"&size=" + size;
		}

		/// <summary>
		/// Generate random data.
		/// </summary>
		/// <param name="length">Record to retrieve.</param>
		/// <param name="size">Length of rach record (HEX16 only).</param>
		/// <returns></returns>
		protected string Next(ushort length, ushort size)
		{
			if (length <= 0 || length > this._Max)
			{
				throw new ArgumentException("Length must be between 1 and " + this._Max + ".");
			}

			if (size <= 0 || size > this._Max)
			{
				throw new ArgumentException("Length must be between 1 and " + this._Max + ".");
			}

			var result = "";

			using (var client = new WebClient())
			{
				var text = client.DownloadString(this.UrlBuilder(length, size));
				var start = text.IndexOf("[");
				result = text.Substring(start + 2, size);
			}
			return result;
		}

		#endregion Protected

		#region Public

		/// <inheritdoc/>
		public string AlgorithmName()
		{
			return "ANU QRNG";
		}

		/// <inheritdoc/>
		public void Reseed()
		{
			// do nothing
		}

		/// <inheritdoc/>
		public bool NextBoolean()
		{
			return this.NextInt() % 2 == 0;
		}

		/// <inheritdoc/>
		public virtual byte NextByte()
		{
			return this.NextBytes(1)[0];
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
			if (length <= 0 || length > this._Max)
			{
				throw new ArgumentException("Length must be between 1 and " + this._Max + ".");
			}

			var result = this.Next(1, (ushort)length);
			return result.DecodeBase16();
		}

		/// <inheritdoc/>
		public uint NextInt()
		{
			return BitConverter.ToUInt32(this.Next(1, 8).DecodeBase16(), 0);
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
			return BitConverter.ToUInt64(this.Next(1, 16).DecodeBase16(), 0);
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
			return this.NextLong() * (1L << 53);
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

		/// <inheritdoc/>
		public override string ToString()
		{
			return this.AlgorithmName();
		}

		#endregion Public
	}

	/// <summary>
	/// Data type of ANU QRNG
	/// </summary>
	public enum ANUType
	{
		//UINT8,
		//UINT16,
		HEX16
	}
}
