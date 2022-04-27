using Gnu.Getopt;
using System;
using System.IO;
using System.Reflection;

namespace cred
{
    class Program
    {
        static void ListCredentials(bool hex)
        {
            try
            {
                foreach (var credential in CredentialManager.EnumerateCredentials(hex))
                {
                    Console.WriteLine(credential);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
            }
        }

        static void ReadCredential(string name, bool hex)
        {
            try
            {
                if (name != null)
                    Console.WriteLine(CredentialManager.ReadCredential(name, hex));
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
            }
        }

        static void WriteCredential(string name, string user, string pass, bool hex)
        {
            try
            {
                if (name != null && user != null && pass != null)
                    CredentialManager.WriteCredential(name, user, pass, hex);
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
            }
        }

        static void Main(string[] args)
        {
            string progname = Path.GetFileName(Assembly.GetExecutingAssembly().CodeBase);

            bool list = false;
            bool read = false;
            bool write = false;
            string name = null;
            string user = null;
            string pass = null;
            bool hex = false;

            Getopt opt = new Getopt(progname, args, "lrwn:u:p:h");
            int c;
            while ((c = opt.getopt()) != -1)
            {
                switch (c)
                {
                    case 'l':
                        list = true;
                        break;
                    case 'r':
                        read = true;
                        break;
                    case 'w':
                        write = true;
                        break;
                    case 'n':
                        name = opt.Optarg;
                        break;
                    case 'u':
                        user = opt.Optarg;
                        break;
                    case 'p':
                        pass = opt.Optarg;
                        break;
                    case 'h':
                        hex = true;
                        break;
                    default:
                        return;
                }
            }

            if (list)
                ListCredentials(hex);

            if (read)
                ReadCredential(name, hex);

            if (write)
                WriteCredential(name, user, pass, hex);
        }
    }
}