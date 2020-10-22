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
			using (RijndaelManaged rijndael = new RijndaelManaged())
			{
				rijndael.BlockSize = 256;
				rijndael.KeySize = 256;
				rijndael.Key = key;
				rijndael.IV = iv;
				rijndael.Mode = CipherMode.CBC;
				rijndael.Padding = PaddingMode.PKCS7;

				ICryptoTransform encryptor = rijndael.CreateEncryptor(rijndael.Key, rijndael.IV);

				using (MemoryStream msEncrypt = new MemoryStream())
				{
					using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
					{
						using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
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
			using (RijndaelManaged rijndael = new RijndaelManaged())
			{
				rijndael.BlockSize = 256;
				rijndael.KeySize = 256;
				rijndael.Key = key;
				rijndael.IV = iv;
				rijndael.Mode = CipherMode.CBC;
				rijndael.Padding = PaddingMode.PKCS7;

				ICryptoTransform decryptor = rijndael.CreateDecryptor(rijndael.Key, rijndael.IV);

				using (MemoryStream msDecrypt = new MemoryStream(data))
				{
					using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
					{
						using (StreamReader srDecrypt = new StreamReader(csDecrypt))
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
			IHash hash = new SHA1();
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

				string certificate_data = cert.CombineVariable();
				certificate_data += ";" + cert.GetChecksum();

				IHash blake2b = new Blake2b(256);
				blake2b.Reset();
				byte[] key = blake2b.ComputeHash(cert.GetUsername());
				blake2b.Reset();
				byte[] iv = blake2b.ComputeHash(this.GetSerialNumber(cert).ToString());
				blake2b.Reset();

				byte[] encrypted_data = this.Encrypt(certificate_data, key, iv);

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
				Certificate certificate = new Certificate();
				
				var encrypted_data = File.ReadAllBytes(location);
				IHash blake2b = new Blake2b(256);
				blake2b.Reset();
				byte[] key = blake2b.ComputeHash(username);
				blake2b.Reset();
				byte[] iv = blake2b.ComputeHash(serial_number);
				blake2b.Reset();

				string decrypt_data = this.Decrypt(encrypted_data, key, iv);
				
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
