﻿using System;

using Litdex.Utilities.Base;

namespace Litdex.Utilities.Extension
{
	/// <summary>
	/// String Extension
	/// </summary>
	public static class StringExtension
	{
		public static string FromBytes(byte[] bs)
		{
			var cs = new char[bs.Length];
			for (var i = 0; i < cs.Length; ++i)
			{
				cs[i] = System.Convert.ToChar(bs[i]);
			}
			return new string(cs);
		}

		public static string FromBytes(this ArraySegment<byte> bytesSegment)
		{
			var bytesArray = bytesSegment.Array;
			var bytesLength = bytesSegment.Count;
			var bytesOffset = bytesSegment.Offset;

			if (bytesLength % 2 != 0)
			{
				throw new ArgumentException($"'{nameof(bytesSegment)}' must have even number of bytes", nameof(bytesSegment));
			}

			var chars = new char[bytesLength / 2];
			for (int i = 0; i < chars.Length; ++i)
			{
				chars[i] = (char)(bytesArray[bytesOffset + (i * 2)] | (bytesArray[bytesOffset + (i * 2) + 1] << 8));
			}
			return new string(chars);
		}

		/// <summary>
		/// Convert byte[] to string.
		/// Encoding UTF-8.
		/// </summary>
		/// <param name="bytes">this byte[].</param>
		/// <returns>string from byte[].</returns>
		public static string GetString(this byte[] bytes)
		{
			return System.Text.Encoding.UTF8.GetString(bytes, 0, bytes.Length);
		}

		/// <summary>
		/// Convert string to Base16.
		/// Encoding UTF-8.
		/// </summary>
		/// <param name="str">string to convert.</param>
		/// <returns>Base16 string.</returns>
		public static string EncodeBase16(this char[] str)
		{
			return EncodeBase16(new string(str));
			//return Base.Base16.Encode(str.GetBytes());
		}

		/// <summary>
		/// Convert string to Base16.
		/// Encoding UTF-8.
		/// </summary>
		/// <param name="str">string to convert.</param>
		/// <returns>Base16 string.</returns>
		public static string EncodeBase16(this string str)
		{
			return Base16.Encode(str.GetBytes());
		}

		/// <summary>
		/// Convert byte[] to Base16.
		/// Encoding UTF-8.
		/// </summary>
		/// <param name="str">byte[] to convert.</param>
		/// <returns>Base16 string.</returns>
		public static string EncodeBase16(this byte[] data)
		{
			return Base16.Encode(data);
		}

		/// <summary>
		/// Convert string to Base64.
		/// Encoding UTF-8.
		/// </summary>
		/// <param name="str">string to convert.</param>
		/// <returns>Base64 string.</returns>
		public static string EncodeBase64(this string data)
		{
			return Base64.Encode(data.GetBytes());
		}

		/// <summary>
		/// Convert byte[] to Base64.
		/// Encoding UTF-8.
		/// </summary>
		/// <param name="str">byte[] to convert.</param>
		/// <returns>Base64 string.</returns>
		public static string EncodeBase64(this byte[] data)
		{
			return Base.Base64.Encode(data);
		}

		/// <summary>
		/// Convert string to Base91.
		/// Encoding UTF-8.
		/// </summary>
		/// <param name="str">string to convert.</param>
		/// <returns>Base91 string.</returns>
		public static string EncodeBase91(this string data)
		{
			return Base.Base91.Encode(data.GetBytes());
		}

		/// <summary>
		/// Convert byte[] to Base91.
		/// Encoding UTF-8.
		/// </summary>
		/// <param name="str">byte[] to convert.</param>
		/// <returns>Base91 string.</returns>
		public static string EncodeBase91(this byte[] data)
		{
			return Base.Base91.Encode(data);
		}

		public static long ToInteger(this string str)
		{
			return long.Parse(str);
		}

	}
}
