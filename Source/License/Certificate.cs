using System;
using System.IO;

using Litdex.Security.Hash;
using Litdex.Utilities.Extension;

//username, start date, end date => di enkripsi

//start date dan end date = 0 => life time certificate

//username dpt berupa email / nama pembeli

//certificate id => binding machine code / dpt dikosongin

namespace Litdex.License
{
	/// <summary>
	/// An electronic document used to prove the ownership.
	/// </summary>
	public class Certificate
	{
		#region Member

		/// <summary>
		/// Certificate ID.
		/// </summary>
		private string _CertificateID;

		/// <summary>
		/// An identification used by a person.
		/// </summary>
		private string _Username;

		/// <summary>
		/// Issued date.
		/// </summary>
		private ulong _StartDate;

		/// <summary>
		/// Expired date.
		/// </summary>
		private ulong _EndDate;

		/// <summary>
		/// Member information integrity checksum.
		/// </summary>
		private string _Checksum;

		#endregion Member

		#region Constructor & Destructor

		/// <summary>
		/// Default constructor.
		/// </summary>
		/// <param name="certificate_id"><see cref="Certificate"></see> Identifier.</param>
		/// <param name="username">Licensee username.</param>
		public Certificate(string certificate_id = "", string username="USERNAME")
		{
			this._CertificateID = certificate_id;
			this._Username = username;
			this._StartDate = (ulong)DateTime.UtcNow.Ticks;
			this._EndDate = (ulong)DateTime.FromFileTimeUtc((long)this._StartDate).AddDays(30).Ticks;
			this._Checksum = "";
		}

		/// <summary>
		/// Destructor.
		/// </summary>
		~Certificate()
		{
			this._CertificateID = this._Username = this._Checksum = "";
			this._StartDate = this._EndDate = 0;
		}

		#endregion Constructor & Destructor

		#region Private Method

		/// <summary>
		/// Hash data with SHA-3.
		/// </summary>
		/// <param name="data">Data to hash.</param>
		/// <returns></returns>
		private string HashData(string data)
		{
			try
			{
				var sha3 = new SHA3(512);
				return sha3.ComputeHash(data).EncodeBase16();
			}
			catch
			{
				throw new InvalidOperationException("Can not calculate SHA-3 checksum.");
			}
		}

		#endregion Private Method

		#region Public Method

		/// <summary>
		/// Set indentification for <see cref="Certificate"/>.
		/// </summary>
		/// <param name="certificate_id">Id for <see cref="Certificate"/></param>
		public void SetCertificateId(string certificate_id)
		{
			if (certificate_id == null)
			{
				return;
			}

			this._CertificateID = certificate_id;
		}

		/// <summary>
		/// Get identification of the <see cref="Certificate"/>.
		/// </summary>
		/// <returns></returns>
		public string GetCertificateId()
		{
			return this._CertificateID;
		}

		/// <summary>
		/// Set licensee username for <see cref="Certificate"/>.
		/// </summary>
		/// <param name="username">Licensee username.</param>
		public void SetUsername(string username)
		{
			if (username == null) 
			{
				return;
			}

			this._Username = username;
		}

		/// <summary>
		/// Get licensee username from <see cref="Certificate"/>.
		/// </summary>
		/// <returns></returns>
		public string GetUsername()
		{
			return this._Username;
		}

		/// <summary>
		/// Set checksum for the <see cref="Certificate"/>.
		/// </summary>
		public void CalculateChecksum()
		{
			string combine = this.CombineVariable();

			if (this._Checksum == "") 
			{
				this._Checksum = this.HashData(combine);
			}
		}

		/// <summary>
		/// Get checksum of the <see cref="Certificate"/>.
		/// </summary>
		/// <returns></returns>
		public string GetChecksum()
		{
			return this._Checksum;
		}

		/// <summary>
		/// Set start date of the <see cref="Certificate"/> in UTC format.
		/// </summary>
		/// <param name="date">Date time.</param>
		public void SetStartDate(DateTime date)
		{
			this.SetStartDate((ulong)date.Ticks);
		}

		/// <summary>
		/// Set start date of the <see cref="Certificate"/> with the numbers of ticks.
		/// 1 Ticks = 100 nanoseconds.
		/// 1 Ticks = 10000 miliseconds.
		/// </summary>
		/// <param name="date">Number of ticks.</param>
		public void SetStartDate(ulong date)
		{
			this._StartDate = date;
		}

		/// <summary>
		/// Get start date of the <see cref="Certificate"/>.
		/// </summary>
		/// <returns></returns>
		public ulong GetStartDate()
		{
			return this._StartDate;
			//return DateTime.FromFileTimeUtc((long)this._StartDate);
		}

		/// <summary>
		/// Set end date of the <see cref="Certificate"/> in UTC format.
		/// </summary>
		/// <param name="date">Date time.</param>
		public void SetEndDate(DateTime date)
		{
			this.SetEndDate((ulong)date.Ticks);
		}

		/// <summary>
		/// Set end date og the <see cref="Certificate"/> with the numbers of ticks.
		/// 1 Ticks = 100 nanoseconds.
		/// 1 Ticks = 10000 miliseconds.
		/// </summary>
		/// <param name="date"></param>
		public void SetEndDate(ulong date)
		{
			this._EndDate = date;
		}

		/// <summary>
		/// Get end date of the <see cref="Certificate"/>.
		/// </summary>
		/// <returns></returns>
		public ulong GetEndDate()
		{
			return this._EndDate;
			//return DateTime.FromFileTimeUtc((long)this._EndDate);
		}

		/// <summary>
		/// Check if the <see cref="Certificate"/> is epired or not.
		/// </summary>
		/// <returns><see langword="true"/> id <see cref="Certificate"/> is expireed. <see langword="false"/> otherwise.</returns>
		public bool IsExpired()
		{
			if (this._StartDate == 0 && this._EndDate == 0) //life time license
			{
				return false;
			}
			else if ((ulong)DateTime.UtcNow.Ticks > this.GetEndDate()) 
			{
				return true;
			}
			return false;
		}

		/// <summary>
		/// Check validity of information in <see cref="Certificate"/>.
		/// </summary>
		/// <returns></returns>
		public bool IsValid()
		{
			if (this._Checksum == this.HashData(this.CombineVariable())) 
			{
				return true;
			}
			return false;
		}

		/// <summary>
		/// Combine variable of <see cref="Certificate"/> into 1 <see cref="string"/>.
		/// </summary>
		/// <returns></returns>
		public string CombineVariable()
		{
			string combine = this._CertificateID + ";";
			combine += this._Username + ";";
			combine += this._StartDate + ";";
			combine += this._EndDate;
			return combine;
		}

		/// <summary>
		/// Split combined variable to respected variable in <see cref="Certificate"/>.
		/// </summary>
		/// <param name="combined_variable"></param>
		public void SplitVariable(string combined_variable)
		{
			string[] split = combined_variable.Split(';');
			this._CertificateID = split[0];
			this._Username = split[1];
			this._StartDate = Convert.ToUInt64(split[2]);
			this._EndDate = Convert.ToUInt64(split[3]);
			this._Checksum = split[4];
		}

		/// <summary>
		/// Create a copy of this <see cref="Certificate"/> without encryption.
		/// </summary>
		/// <param name="location">File location to write.</param>
		/// <returns></returns>
		public bool CopyToFile(string location)
		{
			if (File.Exists(location))
			{
				File.Delete(location);
			}

			try
			{
				using (StreamWriter sw = new StreamWriter(location, false, System.Text.Encoding.UTF8)) 
				{
					sw.WriteLine(this._CertificateID);
					sw.WriteLine(this._Username);
					sw.WriteLine(this._StartDate);
					sw.WriteLine(this._EndDate);
					sw.WriteLine(this._Checksum);
					sw.Flush();
					sw.Close();
				}
				return true;
			}
			catch
			{
				return false;
			}
		}

		/// <summary>
		/// Read <see cref="Certificate"/> file that not encrypted and copy the data into this <see cref="Certificate"/>.
		/// </summary>
		/// <param name="location">File location to read.</param>
		/// <returns></returns>
		public bool CopyFromFile(string location)
		{
			if (File.Exists(location) == false)
			{
				return false;
			}

			try
			{
				using (StreamReader sr = new StreamReader(location, System.Text.Encoding.UTF8))
				{
					this._CertificateID = sr.ReadLine();
					this._Username = sr.ReadLine();
					this._StartDate = ulong.Parse(sr.ReadLine());
					this._EndDate = ulong.Parse(sr.ReadLine());
					this._Checksum = sr.ReadLine();
					sr.Close();
				}
				return true;
			}
			catch
			{
				return false;
			}
		}

		#endregion Public Method
	}
}
