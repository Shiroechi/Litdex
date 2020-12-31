using System;
using System.IO;
using System.Security.Cryptography;

using Litdex.Security.Hash;
using Litdex.Utilities.Extension;

using SHA1 = Litdex.Security.Hash.SHA1;

namespace Litdex.License
{
	public class LicenseManager
	{
		#region Member

		#endregion Member

		#region Constructor & Destructor

		/// <summary>
		/// 
		/// </summary>
		public LicenseManager()
		{

		}

		/// <summary>
		/// 
		/// </summary>
		~LicenseManager()
		{

		}

		#endregion Constructor & Destructor

		#region Private Method

		/// <summary>
		/// Encrypt <see cref="Certificate"/> data with <see cref="Rijndael"/> 256.
		/// </summary>
		/// <param name="data">data to encrypt.</param>
		/// <param name="key">Key to encrypt.</param>
		/// <param name="iv">IV to encrypt.</param>
		/// <returns></returns>
		private byte[] Encrypt(string data, byte[] key, byte[] iv)
		{
			using (var rijndael = new RijndaelManaged())
			{
#if NETCOREAPP2_1
				rijndael.BlockSize = 128;
				rijndael.KeySize = 128;
#elif NETSTANDARD2_0
				rijndael.BlockSize = 256;
				rijndael.KeySize = 256;
#endif
				rijndael.Key = key;
				rijndael.IV = iv;
				rijndael.Mode = CipherMode.CBC;
				rijndael.Padding = PaddingMode.PKCS7;

				var encryptor = rijndael.CreateEncryptor(rijndael.Key, rijndael.IV);

				using (var msEncrypt = new MemoryStream())
				{
					using (var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
					{
						using (var swEncrypt = new StreamWriter(csEncrypt))
						{
							//Write all data to the stream.
							swEncrypt.Write(data);
						}
						return msEncrypt.ToArray();
					}
				}
			}
		}

		/// <summary>
		/// Decrypt <see cref="Certificate"/> data.
		/// </summary>
		/// <param name="data">Data to decrypt.</param>
		/// <param name="key">Key to decrypt.</param>
		/// <param name="iv">IV to decrypt.</param>
		/// <returns></returns>
		private string Decrypt(byte[] data, byte[] key, byte[] iv)
		{
			using (var rijndael = new RijndaelManaged())
			{
#if NETCOREAPP2_1
				rijndael.BlockSize = 128;
				rijndael.KeySize = 128;
#elif NETSTANDARD2_0
				rijndael.BlockSize = 256;
				rijndael.KeySize = 256;
#endif
				rijndael.Key = key;
				rijndael.IV = iv;
				rijndael.Mode = CipherMode.CBC;
				rijndael.Padding = PaddingMode.PKCS7;

				var decryptor = rijndael.CreateDecryptor(rijndael.Key, rijndael.IV);

				using (var msDecrypt = new MemoryStream(data))
				{
					using (var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
					{
						using (var srDecrypt = new StreamReader(csDecrypt))
						{
							return srDecrypt.ReadToEnd();
						}
					}
				}
			}
		}

		/// <summary>
		/// Create Serial Number.
		/// </summary>
		/// <param name="username">Licensee username.</param>
		/// <returns></returns>
		private byte[] SerialNumberGenerator(string username)
		{
			var hash = new SHA1();
			return hash.ComputeHash(username).SubByte(0, 8);
		}

		#endregion Private Method

		#region Public Method

		/// <summary>
		/// Write <see cref="Certificate"/> file to storage.
		/// </summary>
		/// <param name="cert"><see cref="Certificate"/> to write.</param>
		/// <param name="location">File location.</param>
		/// <returns><see langword="true"/> if certificate file succesfully created. <see langword="false"/> otherwise.</returns>
		public bool WriteCertificate(Certificate cert, string location)
		{
			if (File.Exists(location))
			{
				//return false;
				File.Delete(location);
			}

			try
			{
				cert.CalculateChecksum();

				var certificate_data = cert.CombineVariable();
				certificate_data += ";" + cert.GetChecksum();

#if NETCOREAPP2_1
				var blake2b = new Blake2b(128);
#elif NETSTANDARD2_0
				var blake2b = new Blake2b(256);
#endif
				blake2b.Reset();
				var key = blake2b.ComputeHash(cert.GetUsername());
				blake2b.Reset();
				var iv = blake2b.ComputeHash(this.GetSerialNumber(cert).ToString());
				blake2b.Reset();
				var encrypted_data = this.Encrypt(certificate_data, key, iv);

				File.WriteAllBytes(location, encrypted_data);

				return true;
			}
			catch
			{
				return false;
			}
		}

		/// <summary>
		/// Read <see cref="Certificate"/> file.
		/// </summary>
		/// <param name="location">File location.</param>
		/// <param name="username">Licensee username.</param>
		/// <param name="serial_number">Product serial number.</param>
		/// <returns></returns>
		public Certificate ReadCertificate(string location, string username, string serial_number)
		{
			if (File.Exists(location) == false)
			{
				return null;
			}

			try
			{
				var certificate = new Certificate();

				var encrypted_data = File.ReadAllBytes(location);
				var blake2b = new Blake2b(256);
				blake2b.Reset();
				var key = blake2b.ComputeHash(username);
				blake2b.Reset();
				var iv = blake2b.ComputeHash(serial_number);
				blake2b.Reset();

				var decrypt_data = this.Decrypt(encrypted_data, key, iv);

				certificate.SplitVariable(decrypt_data);

				return certificate;
			}
			catch
			{
				return null;
			}
		}

		/// <summary>
		/// Get Serial Number based on <see cref="Certificate"/>.
		/// </summary>
		/// <param name="cert">Licensee <see cref="Certificate"/>.</param>
		/// <returns></returns>
		public string GetSerialNumber(Certificate cert)
		{
			if (cert == null)
			{
				throw new ArgumentException("Certificate can not null.");
			}

			return this.GetSerialNumber(cert.GetUsername());
		}

		/// <summary>
		/// Get Serial Number based on licensee username.
		/// </summary>
		/// <param name="username">Licensee username.</param>
		/// <returns></returns>
		public string GetSerialNumber(string username)
		{
			if (username.Trim().Length <= 0)
			{
				throw new ArgumentException("Username can't empty.");
			}

			username = username.Trim().ToLower();
			return BitConverter.ToUInt64(this.SerialNumberGenerator(username), 0).ToString();
		}

		/// <summary>
		/// Verify serial number.
		/// </summary>
		/// <param name="username">Licensee username.</param>
		/// <param name="serial_number">Licensee serial number.</param>
		/// <returns></returns>
		public bool VerifySerialNumber(string username, string serial_number)
		{
			if (this.GetSerialNumber(username) == serial_number)
			{
				return true;
			}
			return false;
		}

		#endregion Public Method
	}
}
