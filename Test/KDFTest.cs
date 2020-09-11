using System;
using System.Threading;

using Litdex.Security.KDF;
using Litdex.Utilities.Extension;

namespace Litdex.Test
{
	class KDFTest
	{
		static void Main(string[] args)
		{
			Thread.Sleep(2000);
			Console.WriteLine("Starting...\n");

			//------------------------------------------------------------

			//test case from https://tools.ietf.org/html/rfc6070
			Console.WriteLine("PBKDF2 Test \n");

			PBKDF2 pbkdf = new PBKDF2();

			Console.WriteLine("First Test Case \n");
			string pass = "password";
			string salt = "salt";
			int c = 1;
			int dklen = 20;

			Console.WriteLine("PBKDF2 name = " + pbkdf.AlgorithmName());
			Console.WriteLine("Password = " + pass);
			Console.WriteLine("Salt = " + salt);
			Console.WriteLine("Iteration = " + c);
			Console.WriteLine("Output Length = " + dklen);

			var result = pbkdf.Derive(pass.GetBytes(), salt.GetBytes(), dklen, c).EncodeBase16();

			Console.WriteLine("Output			=	" + result);;
			Console.WriteLine("Output from RFC 6070	=	" + "0c60c80f961f0e71f3a9b524af6012062fe037a6".ToUpper());

			Console.WriteLine("Compare result = " + (result.ToLower() == "0c60c80f961f0e71f3a9b524af6012062fe037a6"));


			Console.WriteLine("Second Test Case \n");
			pass = "password";
			salt = "salt";
			c = 2;
			dklen = 20;

			Console.WriteLine("PBKDF2 name = " + pbkdf.AlgorithmName());
			Console.WriteLine("Password = " + pass);
			Console.WriteLine("Salt = " + salt);
			Console.WriteLine("Iteration = " + c);
			Console.WriteLine("Output Length = " + dklen);

			result = pbkdf.Derive(pass.GetBytes(), salt.GetBytes(), dklen, c).EncodeBase16();

			Console.WriteLine("Output			=	" + result); ;
			Console.WriteLine("Output from RFC 6070	=	" + "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957".ToUpper());

			Console.WriteLine("Compare result = " + (result.ToLower() == "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957"));


			//------------------------------------------------------------

			Console.WriteLine("\nProgram End.");
			Console.ReadKey();
			Console.ReadKey();
		}
	}
}
