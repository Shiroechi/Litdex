using System;
using System.Threading;

using Litdex.Security.OTP;
using Litdex.Utilities.Extension;

namespace Litdex.Test
{
	class OTPTest
	{
		static void Main(string[] args)
		{
			Thread.Sleep(2000);
			Console.WriteLine("Starting...\n");

			//------------------------------------------------------------

			Console.WriteLine("OTP TEST");
			Console.WriteLine();

			Console.WriteLine("HOTP SECTION TEST");

			HOTP hotp = new HOTP(6);
			byte[] key = "12345678901234567890".GetBytes();

			Console.WriteLine("Key = " + 12345678901234567890);

			Console.WriteLine(hotp.Generate(key, 0) == "755224");
			Console.WriteLine(hotp.Generate(key, 1) == "287082");
			Console.WriteLine(hotp.Generate(key, 2) == "359152");
			Console.WriteLine(hotp.Generate(key, 3) == "969429");
			Console.WriteLine(hotp.Generate(key, 4) == "338314");
			Console.WriteLine(hotp.Generate(key, 5) == "254676");
			Console.WriteLine(hotp.Generate(key, 6) == "287922");
			Console.WriteLine(hotp.Generate(key, 7) == "162583");
			Console.WriteLine(hotp.Generate(key, 8) == "399871");
			Console.WriteLine(hotp.Generate(key, 9) == "520489");




			Console.WriteLine("TOTP SECTION TEST");

			TOTP totp = new TOTP(6);
			Console.WriteLine("Key = " + 12345678901234567890);

			DateTime now = DateTime.UtcNow;
			Console.WriteLine("Date time = " + now.ToString());
			Console.WriteLine("Ticks	 = " + now.Ticks);
			Console.WriteLine("Seconds	 = " + now.Ticks / 10000000);

			Console.WriteLine();
			string otp = totp.Generate(key, now.Ticks);
			Console.WriteLine("Code = " + otp + "\n");

			Console.WriteLine("\n" + "Wait 5 Seconds" + "\n");

			Console.WriteLine("Date time = " + new DateTime(now.Ticks + 50000000).ToString());
			Console.WriteLine("Ticks	 = " + now.Ticks + 50000000);
			Console.WriteLine("Seconds	 = " + (now.Ticks + 50000000) / 10000000);

			Console.WriteLine("Verify 1 = " + totp.Verify(otp, key, now.Ticks + 50000000));
			Console.WriteLine("Verify 2 = " + totp.Verify2(otp, key, now.Ticks + 50000000));

			//------------------------------------------------------------

			Console.WriteLine("\nProgram End.");
			Console.ReadKey();
			Console.ReadKey();
		}
	}
}
