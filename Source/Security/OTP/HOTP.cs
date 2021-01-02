using System;

namespace Litdex.Security.OTP
{
	//test case
	//
	//Key (in string)	= 12345678901234567890
	//key (in hex)		= 0x3132333435363738393031323334353637383930
	//
	// detail of counter and HMAC value 
	// Count	 Hexadecimal HMAC-SHA-1(secret, count)
	// 0        cc93cf18508d94934c64b65d8ba7667fb7cde4b0
	// 1        75a48a19d4cbe100644e8ac1397eea747a2d33ab
	// 2        0bacb7fa082fef30782211938bc1c5e70416ff44
	// 3        66c28227d03a2d5529262ff016a1e6ef76557ece
	// 4        a904c900a64b35909874b33e61c5938a8e15ed1c
	// 5        a37e783d7b7233c083d4f62926c7a25f238d0316
	// 6        bc9cd28561042c83f219324d3c607256c03272ae
	// 7        a4fb960c0bc06e1eabb804e5b397cdc4b45596fa
	// 8        1b3c89f65e6c9e883012052823443f048b4332db
	// 9        1637409809a679dc698207310c8c7fc07290d9e5
	//
	// result
	// Count   Hexadecimal		 Decimal	   HOTP
	// 0        4c93cf18       1284755224     755224
	// 1        41397eea       1094287082     287082
	// 2         82fef30        137359152     359152
	// 3        66ef7655       1726969429     969429
	// 4        61c5938a       1640338314     338314
	// 5        33c083d4        868254676     254676
	// 6        7256c032       1918287922     287922
	// 7         4e5b397         82162583     162583
	// 8        2823443f        673399871     399871
	// 9        2679dc69        645520489     520489

	/// <summary>
	/// <para>
	/// HMAC-based One-time Password algorithm (HOTP) 
	/// is a one-time password (OTP) algorithm based on HMAC. 
	/// </para>
	/// <para>
	/// This <see cref="HOTP"/> class based on implementation RFC 4226
	/// https://tools.ietf.org/html/rfc4226
	/// </para>
	/// </summary>
	public class HOTP : OTP
	{
		#region Constructor & Destructor 

		/// <summary>
		/// Create HMAC-based One-time Password with
		/// custom digit number.
		/// </summary>
		/// <param name="length">Output digits.</param>
		public HOTP(int length = 6) : this(length, OTPHashMode.SHA1)
		{

		}

		/// <summary>
		/// Create HMAC-based One-time Password with
		/// custom digit number and custom hash mode.
		/// </summary>
		/// <param name="length">Number of digit to produce.</param>
		public HOTP(int length, OTPHashMode mode) : base(length, mode)
		{

		}

		/// <summary>
		/// Destructor.
		/// </summary>
		~HOTP()
		{
			Array.Clear(this._Key, 0, this._Key.Length);
		}

		#endregion Constructor & Destructor

		#region Public

		/// <summary>
		/// Generate password.
		/// </summary>
		/// <returns></returns>
		public string Generate()
		{
			if (this._Key == null || this._Key.Length <= 0)
			{
				this.GenerateKey(32);
			}
			this._Counter++;
			return this.GeneratePassword(this._Key, this._Counter);
		}

		/// <summary>
		/// Generate password.
		/// </summary>
		/// <param name="key">Pre-shared key.</param>
		/// <param name="counter">State counter.</param>
		/// <returns></returns>
		public string Generate(byte[] key, ulong counter)
		{
			return this.GeneratePassword(key, counter);
		}

		/// <summary>
		/// Verify inputed password with 
		/// password that generated from <see cref="Generate(byte[], long)"/>.
		/// </summary>
		/// <param name="input">Inputed password.</param>
		/// <param name="key">Pre-shared key.</param>
		/// <param name="counter">State counter.</param>
		/// <returns></returns>
		public bool Verify(string input, byte[] key, ulong counter)
		{
			if (input == this.GeneratePassword(key, counter))
			{
				return true;
			}

			return false;
		}

		#endregion Public
	}
}
