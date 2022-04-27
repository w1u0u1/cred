// The most up to date version is available 
// on GitHub: https://github.com/meziantou/Meziantou.Framework/tree/master/src/Meziantou.Framework.Win32.CredentialManager
// NuGet package: https://www.nuget.org/packages/Meziantou.Framework.Win32.CredentialManager/

using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace cred
{
    enum CredentialType
    {
        Generic = 1,
        DomainPassword,
        DomainCertificate,
        DomainVisiblePassword,
        GenericCertificate,
        DomainExtended,
        Maximum,
        MaximumEx = Maximum + 1000,
    }

    class CredentialManager
    {
        public static Credential ReadCredential(string applicationName, bool hex)
        {
            IntPtr nCredPtr;
            bool read = CredRead(applicationName, CredentialType.Generic, 0, out nCredPtr);
            if (read)
            {
                using (CriticalCredentialHandle critCred = new CriticalCredentialHandle(nCredPtr))
                {
                    CREDENTIAL cred = critCred.GetCredential();
                    return ReadCredential(cred, hex);
                }
            }

            return null;
        }

        private static Credential ReadCredential(CREDENTIAL credential, bool hex)
        {
            string applicationName = Marshal.PtrToStringUni(credential.TargetName);
            string userName = Marshal.PtrToStringUni(credential.UserName);
            string secret = null;
            if (credential.CredentialBlob != IntPtr.Zero)
            {
                if (hex)
                {
                    byte[] buf = new byte[credential.CredentialBlobSize];
                    Marshal.Copy(credential.CredentialBlob, buf, 0, (int)credential.CredentialBlobSize);
                    secret = BitConverter.ToString(buf).Replace("-", "");
                }
                else
                    secret = Marshal.PtrToStringUni(credential.CredentialBlob, (int)credential.CredentialBlobSize / 2);
            }

            return new Credential(credential.Type, applicationName, userName, secret);
        }

        public static byte[] StringToByteArray(string hex)
        {
            return Enumerable.Range(0, hex.Length)
                             .Where(x => x % 2 == 0)
                             .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
                             .ToArray();
        }

        public static void WriteCredential(string applicationName, string userName, string secret, bool hex = false)
        {
            byte[] byteArray = null;

            if (!hex)
                byteArray = secret == null ? null : Encoding.Unicode.GetBytes(secret);
            else
                byteArray = StringToByteArray(secret);

            // XP and Vista: 512; 
            // 7 and above: 5*512
            if (Environment.OSVersion.Version < new Version(6, 1) /* Windows 7 */)
            {
                if (byteArray != null && byteArray.Length > 512)
                    throw new ArgumentOutOfRangeException("secret", "The secret message has exceeded 512 bytes.");
            }
            else
            {
                if (byteArray != null && byteArray.Length > 512 * 5)
                    throw new ArgumentOutOfRangeException("secret", "The secret message has exceeded 2560 bytes.");
            }

            CREDENTIAL credential = new CREDENTIAL();
            credential.AttributeCount = 0;
            credential.Attributes = IntPtr.Zero;
            credential.Comment = IntPtr.Zero;
            credential.TargetAlias = IntPtr.Zero;
            credential.Type = CredentialType.Generic;
            credential.Persist = (uint)CredentialPersistence.LocalMachine;
            credential.CredentialBlobSize = (uint)(byteArray == null ? 0 : byteArray.Length);
            credential.TargetName = Marshal.StringToCoTaskMemUni(applicationName);

            //credential.CredentialBlob = Marshal.StringToCoTaskMemUni(secret);
            GCHandle blob = GCHandle.Alloc(byteArray, GCHandleType.Pinned);
            credential.CredentialBlob = blob.AddrOfPinnedObject();

            credential.UserName = Marshal.StringToCoTaskMemUni(userName ?? Environment.UserName);

            bool written = CredWrite(ref credential, 0);
            Marshal.FreeCoTaskMem(credential.TargetName);
            //Marshal.FreeCoTaskMem(credential.CredentialBlob);
            blob.Free();
            Marshal.FreeCoTaskMem(credential.UserName);

            if (!written)
            {
                int lastError = Marshal.GetLastWin32Error();
                throw new Exception(string.Format("CredWrite failed with the error code {0}.", lastError));
            }
        }

        public static List<Credential> EnumerateCredentials(bool hex)
        {
            List<Credential> result = new List<Credential>();

            int count;
            IntPtr pCredentials;
            bool ret = CredEnumerate(null, 0, out count, out pCredentials);
            if (ret)
            {
                for (int n = 0; n < count; n++)
                {
                    IntPtr credential = Marshal.ReadIntPtr(pCredentials, n * Marshal.SizeOf(typeof(IntPtr)));
                    result.Add(ReadCredential((CREDENTIAL)Marshal.PtrToStructure(credential, typeof(CREDENTIAL)), hex));
                }
            }
            else
            {
                int lastError = Marshal.GetLastWin32Error();
                throw new Win32Exception(lastError);
            }

            return result;
        }

        [DllImport("Advapi32.dll", EntryPoint = "CredReadW", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern bool CredRead(string target, CredentialType type, int reservedFlag, out IntPtr credentialPtr);

        [DllImport("Advapi32.dll", EntryPoint = "CredWriteW", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern bool CredWrite([In] ref CREDENTIAL userCredential, [In] UInt32 flags);

        [DllImport("advapi32", SetLastError = true, CharSet = CharSet.Unicode)]
        static extern bool CredEnumerate(string filter, int flag, out int count, out IntPtr pCredentials);

        [DllImport("Advapi32.dll", EntryPoint = "CredFree", SetLastError = true)]
        static extern bool CredFree([In] IntPtr cred);

        private enum CredentialPersistence : uint
        {
            Session = 1,
            LocalMachine,
            Enterprise
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct CREDENTIAL
        {
            public uint Flags;
            public CredentialType Type;
            public IntPtr TargetName;
            public IntPtr Comment;
            public System.Runtime.InteropServices.ComTypes.FILETIME LastWritten;
            public uint CredentialBlobSize;
            public IntPtr CredentialBlob;
            public uint Persist;
            public uint AttributeCount;
            public IntPtr Attributes;
            public IntPtr TargetAlias;
            public IntPtr UserName;
        }

        sealed class CriticalCredentialHandle : CriticalHandleZeroOrMinusOneIsInvalid
        {
            public CriticalCredentialHandle(IntPtr preexistingHandle)
            {
                SetHandle(preexistingHandle);
            }

            public CREDENTIAL GetCredential()
            {
                if (!IsInvalid)
                {
                    CREDENTIAL credential = (CREDENTIAL)Marshal.PtrToStructure(handle, typeof(CREDENTIAL));
                    return credential;
                }

                throw new InvalidOperationException("Invalid CriticalHandle!");
            }

            protected override bool ReleaseHandle()
            {
                if (!IsInvalid)
                {
                    CredFree(handle);
                    SetHandleAsInvalid();
                    return true;
                }

                return false;
            }
        }
    }
}