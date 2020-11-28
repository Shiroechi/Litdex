using System;

using Litdex.Security.Hash;
using Litdex.Security.MAC;

namespace Litdex.Security.KDF
{
	/// <summary>
	/// HMAC-based Key Derivation Function.
	/// RFC 5869
	/// </summary>
	public class HKDF
	{
		#region Member

		private readonly IMAC _MAC;

		#endregion Member

		/// <summary>
		/// Constructor.
		/// </summary>
		public HKDF()
		{
			this._MAC = new HMAC(new SHA1());
		}

		/// <summary>
		/// Constructor.
		/// </summary>
		/// <param name="hash">Hash function.</param>
		public HKDF(IHash hash)
		{
			this._MAC = new HMAC(hash);
		}

		/// <summary>
		/// Destructor.
		/// </summary>
		~HKDF()
		{
			this.Reset();
		}

		#region Private

		/// <summary>
		/// Create a pseudorandom key.
		/// </summary>
		/// <param name="salt">Optional salt value.</param>
		/// <param name="InputKeyMaterial">Input key material.</param>
		/// <returns></returns>
		private byte[] Extract(byte[] salt, byte[] InputKeyMaterial)
		{
			if (salt == null)
			{
				salt = new byte[this._MAC.GetHashFunction().GetHashLength()];
				for (var i = 0; i < salt.Length; i++)
				{
					salt[i] = 0;
				}
			}

			return this._MAC.ComputeHash(salt, InputKeyMaterial);
		}

		/// <summary>
		/// Expand key.
		/// </summary>
		/// <param name="prk">A pseudorandom key.</param>
		/// <param name="info">Optional context and application specific information.</param>
		/// <param name="length">Length of output keying materials.</param>
		/// <returns></returns>
		private byte[] Expand(byte[] prk, byte[] info, int length)
		{
			if (prk.Length < this._MAC.GetHashLength())
			{
				throw new ArgumentException(
					"Pseudorandom key length is " + prk.Length +
					" lower than " + this._MAC.GetHashLength());
			}
			if (info == null)
			{
				info = Array.Empty<byte>();
			}
			if (length < 0)
			{
				throw new ArgumentException("Length can't be 0.");
			}
			if (length > this._MAC.GetHashLength() * 255)
			{
				throw new ArgumentException("Length can't exceed " + this._MAC.GetHashLength() * 255);
			}

			var resultBlock = new byte[0];
			var result = new byte[length];
			var bytesRemaining = length;

			for (int i = 1; bytesRemaining > 0; i++)
			{
				var currentInfo = new byte[resultBlock.Length + info.Length + 1];
				Buffer.BlockCopy(resultBlock, 0, currentInfo, 0, resultBlock.Length);
				Buffer.BlockCopy(info, 0, currentInfo, resultBlock.Length, info.Length);
				currentInfo[currentInfo.Length - 1] = (byte)i;
				resultBlock = this.Extract(prk, currentInfo);
				Buffer.BlockCopy(resultBlock, 0, result, length - bytesRemaining, Math.Min(resultBlock.Length, bytesRemaining));
				bytesRemaining -= resultBlock.Length;
			}
			return result;
		}

		//public byte[] DeriveKey(byte[] data, byte[] salt, byte[] info, int length)
		//{
		//	//Extract phase
		//	byte[] prk = this.CreatePRK(salt, data);

		//	//Expand phase
		//	int iteration = (int)Math.Ceiling((double)(length / this._MAC.GetHashFunction().GetHashLength()));
		//	this._MAC.Initialize(prk);
		//	byte[] result = null;
		//	byte[] temp = new byte[0];
		//	int remaining = length;
		//	int step = 0;

		//	using (MemoryStream stream = new MemoryStream())
		//	{
		//		for (int i = 0; i < iteration; i++)
		//		{
		//			this._MAC.Update(temp);
		//			this._MAC.Update(info);
		//			this._MAC.Update(new byte[] { (byte)(i + 1) });
		//			this._MAC.DoFinal(temp, 0);

		//			step = Math.Min(remaining, temp.Length);
		//			stream.Write(temp, 0, step);
		//		}
		//		stream.ToArray().CopyTo(result, 0);
		//		remaining -= step;
		//	}

		//	return result;
		//}

		#endregion Private

		#region Public

		/// <summary>
		/// Return the name of the algorithm the KDF implements.
		/// </summary>
		/// <returns></returns>
		public string AlgorithmName()
		{
			return "HKDF-" + this._MAC.GetHashFunction().AlgorithmName();
		}

		/// <summary>
		/// Reset the HKDF.
		/// </summary>
		public void Reset()
		{
			this._MAC.Reset();
		}

		/// <summary>
		/// Computes the derived key for specified byte array. 
		/// </summary>
		/// <param name="data">Data to derive.</param>
		/// <param name="salt">Additional byte array.</param>
		/// <param name="length">Output length.</param>
		/// <returns></returns>
		public byte[] Derive(byte[] data, byte[] salt, byte[] info, int length)
		{
			byte[] prk = this.Extract(salt, data);
			byte[] result = this.Expand(prk, info, length);
			return result;
		}

		#endregion Public
	}
}
