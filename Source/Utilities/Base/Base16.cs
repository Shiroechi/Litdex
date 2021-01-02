using System;

namespace Litdex.Utilities.Base
{
	/// <summary>
	///		Encode and decode in base 16 (hexadecimal).
	/// </summary>
	public static class Base16
	{
		/// <summary>
		///		Encode <paramref name="data"/> to hexadecimal <see cref="string"/>.
		/// </summary>
		/// <param name="data">
		///		Arrays of <see cref="byte"/> to encode.
		///	</param>
		/// <param name="upper">
		///		<see langword="true"/> Output <see cref="string"/> in upper case; <see langword="false"/> otherwise.
		///	</param>
		/// <returns>
		///		Hexadecimal <see cref="string"/>.
		/// </returns>
		/// <exception cref="ArgumentNullException">
		///		<paramref name="data"/> is null or empty.
		/// </exception>
		public static string Encode(byte[] data, bool upper = true)
		{
			if (data == null || data.Length == 0)
			{
				throw new ArgumentNullException(nameof(data), "Array can't null or empty.");
			}

			if (upper)
			{
				return EncodeUpper(data);
			}
			return EncodeLower(data);
		}

		/// <summary>
		///		Encode arrays of <see cref="byte"/> to hexadecimal string in upper case.
		/// </summary>
		/// <param name="data">
		///		Arrays of <see cref="byte"/> to encode.
		///	</param>
		/// <returns>
		///		Hexadecimal string in upper case.
		/// </returns>
		private static string EncodeUpper(byte[] data)
		{
			var c = new char[data.Length * 2];
			int b;
			for (var i = 0; i < data.Length; i++)
			{
				b = data[i] >> 4;
				c[i * 2] = (char)(55 + b + (((b - 10) >> 31) & -7));
				b = data[i] & 0xF;
				c[(i * 2) + 1] = (char)(55 + b + (((b - 10) >> 31) & -7));
			}
			return new string(c);
		}

		/// <summary>
		///		Encode arrays of <see cref="byte"/> to hexadecimal string in lower case.
		/// </summary>
		/// <param name="data">
		///		Arrays of <see cref="byte"/> to encode.
		///	</param>
		/// <returns>
		///		Hexadecimal string in lower case.
		/// </returns>
		private static string EncodeLower(byte[] data)
		{
			var c = new char[data.Length * 2];
			int b;
			for (var i = 0; i < data.Length; i++)
			{
				b = data[i] >> 4;
				c[i * 2] = (char)(87 + b + (((b - 10) >> 31) & -39));
				b = data[i] & 0xF;
				c[(i * 2) + 1] = (char)(87 + b + (((b - 10) >> 31) & -39));
			}
			return new string(c);
		}

		/// <summary>
		///		Decode hexadecimal string to arrays of <see cref="byte"/>.
		/// </summary>
		/// <param name="hexString">
		///		Hexadecimal string to decode.
		///	</param>
		/// <returns>
		///		Arrays of <see cref="byte"/> of decoded <paramref name="hexString"/>.
		/// </returns>
		/// <exception cref="ArgumentNullException">
		///		<paramref name="hexString"/> is null, empty or containing white spaces.
		/// </exception>
		/// <exception cref="ArgumentOutOfRangeException">
		///		<paramref name="hexString"/> length is odd.
		/// </exception>
		public static byte[] Decode(string hexString)
		{
			if (string.IsNullOrWhiteSpace(hexString))
			{
				throw new ArgumentNullException(nameof(hexString), "Hexadecimal string can't null, empty or containing white spaces.");
			}

			if (hexString.Length % 2 != 0)
			{
				throw new ArgumentOutOfRangeException(nameof(hexString), "The hexadecimal string is invalid because it has an odd length.");
			}

			var result = new byte[hexString.Length / 2];

			for (var i = 0; i < result.Length; i++)
			{
				int high = hexString[i * 2];
				int low = hexString[i * 2 + 1];
				high = (high & 0xf) + ((high & 0x40) >> 6) * 9;
				low = (low & 0xf) + ((low & 0x40) >> 6) * 9;

				result[i] = (byte)((high << 4) | low);
			}

			return result;
		}
	}
}