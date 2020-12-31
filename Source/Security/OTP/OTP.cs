using System;

using Litdex.Security.Hash;
using Litdex.Security.MAC;
using Litdex.Security.RNG;
using Litdex.Security.RNG.CSPRNG;
using Litdex.Utilities.Extension;

namespace Litdex.Security.OTP
{
	/// <summary>
	/// Base class for One Time Password.
	/// This <see cref="OTP"/> implementation not based on RFC 2289.
	/// </summary>
	public abstract class OTP
	{
		#region Member

		/// <summary>
		/// Custom One Time Password hash mode.
		/// </summary>
		protected OTPHashMode _HashMode;

		/// <summary>
		/// Default output length.
		/// </summary>
		protected int _OutputLength = 0;

		/// <summary>
		/// Minimun output length.
		/// </summary>
		protected readonly int _MinLength = 6;

		/// <summary>
		/// Maximum output length, as RFC 6238 it is 8.
		/// </summary>
		protected readonly int _MaxLength = 10;

		/// <summary>
		/// Pre-shared key.
		/// </summary>
		protected byte[] _Key;

		/// <summary>
		/// State counter.
		/// </summary>
		protected ulong _Counter;

		#endregion Member

		#region Constructor & Destructor

		/// <summary>
		/// Create One Time Password with 
		/// 6 digit number.
		/// </summary>
		public OTP() : this(6)
		{

		}

		/// <summary>
		/// Create One Time Password with
		/// custom digit number and default hash mode SHA1.
		/// </summary>
		/// <param name="length">Number of digit to produce.</param>
		public OTP(int length) : this(length, OTPHashMode.SHA1)
		{

		}

		/// <summary>
		/// Create One Time Password with
		/// custom digit number and default hash mode SHA1.
		/// </summary>
		/// <param name="length">Number of digit to produce.</param>
		public OTP(int length, OTPHashMode mode)
		{
			if ((length < this._MinLength) || (length > this._MaxLength))
			{
				throw new ArgumentException("Output length must be between " + this._MinLength + " and " + this._MaxLength + ".");
			}

			this._Counter = 0;
			this._Key = null;
			this._HashMode = mode;
			this._OutputLength = length;
		}

		/// <summary>
		/// Destrutor.
		/// </summary>
		~OTP()
		{
			this._Key.Clear();
		}

		#endregion Constructor & Destructor

		#region Protected Method

		/// <summary>
		/// Generate random key.
		/// </summary>
		/// <param name="length">Length of random key.</param>
		/// <returns></returns>
		protected byte[] GenerateKey(int length)
		{
			return this.GenerateKey(length, new CryptGenRandom());
		}

		/// <summary>
		/// Generate random key.
		/// </summary>
		/// <param name="length">Length of random key.</param>
		/// <param name="rng">Random numger generator engine.</param>
		/// <returns></returns>
		protected byte[] GenerateKey(int length, IRNG rng)
		{
			IRNG rnd = rng;
			return rnd.NextBytes(length);
		}

		/// <summary>
		/// Generate hash function.
		/// </summary>
		/// <param name="mode">Which hash function to generate.</param>
		/// <returns></returns>
		protected IHash GenerateHashFunction(OTPHashMode mode)
		{
			switch (mode)
			{
				case OTPHashMode.SHA1:
					return new SHA1();

				case OTPHashMode.SHA256:
					return new SHA256();

				case OTPHashMode.SHA512:
					return new SHA512();

				case OTPHashMode.Blake2b:
					return new Blake2b();

				default:
					return new SHA1();
			}
		}

		/// <summary>
		/// Generate One Time Password.
		/// </summary>
		/// <param name="key">Pre-shared key.</param>
		/// <param name="counter">State counter.</param>
		/// <returns></returns>
		protected string GeneratePassword(byte[] key, ulong counter)
		{
			//convert ulong to byte[]
			byte[] text = new byte[8];
			for (int i = text.Length - 1; i >= 0; i--)
			{
				text[i] = (byte)(counter & 0xFF);
				counter >>= 8;
			}

			//compute hmac hash
			IMAC mac = new HMAC(this.GenerateHashFunction(this._HashMode));
			var result = mac.ComputeHash(key, text);

			int offset = result[result.Length - 1] & 0x0F;

			long data = (result[offset] & 0x7f) << 24 |
						(result[offset + 1] & 0xff) << 16 |
						(result[offset + 2] & 0xff) << 8 |
						(result[offset + 3] & 0xff);

			//covert data to readable human text.
			var truncatedValue = data % (long)(Math.Pow(10, this._OutputLength));
			return truncatedValue.ToString().PadLeft(this._OutputLength, '0');
		}

		/// <summary>
		/// Generate One Time Password.
		/// </summary>
		/// <param name="key">Pre-shared key.</param>
		/// <param name="counter">State counter.</param>
		/// <param name="custom_offset">Offset to start truncate.</param>
		/// <returns></returns>
		protected string GeneratePassword(byte[] key, ulong counter, byte custom_offset)
		{
			//convert ulong to byte[]
			byte[] text = new byte[8];
			for (int i = text.Length - 1; i >= 0; i--)
			{
				text[i] = (byte)(counter & 0xFF);
				counter >>= 8;
			}

			//compute hmac hash
			IMAC mac = new HMAC(this.GenerateHashFunction(this._HashMode));
			var result = mac.ComputeHash(key, text);

			// compute custom offset 
			int offset = result[result.Length - 1] & 0x0F;
			if ((custom_offset <= 0) && (custom_offset < (result.Length - 4)))
			{
				offset = custom_offset;
			}

			long data = (result[offset] & 0x7f) << 24 |
						(result[offset + 1] & 0xff) << 16 |
						(result[offset + 2] & 0xff) << 8 |
						(result[offset + 3] & 0xff);

			//covert data to readable human text.
			var truncatedValue = data % (long)(Math.Pow(10, this._OutputLength));
			return truncatedValue.ToString().PadLeft(this._OutputLength, '0');
		}

		#endregion Protected Method

		#region Public

		/// <summary>
		/// Get current counter state.
		/// </summary>
		/// <returns></returns>
		public ulong GetCounter()
		{
			return this._Counter;
		}

		/// <summary>
		/// Get pre-shared key.
		/// </summary>
		/// <returns></returns>
		public byte[] GetKey()
		{
			return this._Key;
		}

		#endregion Public

	}
}
