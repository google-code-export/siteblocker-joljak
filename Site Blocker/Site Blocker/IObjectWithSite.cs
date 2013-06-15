using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

using SHDocVw;
using mshtml;
using System.IO;
using Microsoft.Win32;
using System.Runtime.InteropServices;

namespace Site_Blocker
{
    [ComVisible(true),
    InterfaceType(ComInterfaceType.InterfaceIsIUnknown),
    Guid("140DA4BA-52F9-41D1-9AEB-6B8B4F52DC4D")]
    interface IObjectWithSite
    {
        [PreserveSig]
        int SetSite([MarshalAs(UnmanagedType.IUnknown)]object site);
        [PreserveSig]
        int GetSite(ref Guid guid, out IntPtr ppvSite);
    }
}