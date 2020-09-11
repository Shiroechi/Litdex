using System;
using System.Threading;

using Litdex.License;

namespace Litdex.Test
{
	class LicenseTest
	{
		static void Main(string[] args)
		{
			Thread.Sleep(2000);
			Console.WriteLine("Starting...\n");

			//------------------------------------------------------------

			string path = "D:\\Project\\license.cert";


			// issue certificate and serial number/product key/license key
			
			//create certificate
			Certificate cert = new Certificate();
			cert.SetStartDate(DateTime.UtcNow);
			cert.SetEndDate(DateTime.UtcNow.AddDays(30));
			cert.SetUsername("admin");

			LicenseManager manager = new LicenseManager();
			manager.WriteCertificate(cert, path); //write certificate
			var sn = manager.GetSerialNumber(cert); //get serial number/product key/license key from certificate


			//read certificate
			Certificate cert1 = new Certificate();
			cert1 = manager.ReadCertificate(path, "admin", sn);

			//extract infromation from cretificate
			Console.WriteLine(sn);
			Console.WriteLine(cert1.GetUsername());
			Console.WriteLine(DateTime.FromFileTimeUtc((long)cert1.GetStartDate()));
			Console.WriteLine(DateTime.FromFileTimeUtc((long)cert1.GetEndDate()));
			Console.WriteLine(cert1.GetChecksum());

			Console.WriteLine("Expired = " + cert1.IsExpired()); //subcription status
			Console.WriteLine("Valid = " + cert1.IsValid()); //check infromation validity
			
			//------------------------------------------------------------

			Console.WriteLine("\nProgram End.");
			Console.ReadKey();
			Console.ReadKey();
		}
	}
}
