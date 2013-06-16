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
    Guid("FC4801A3-2BA9-11CF-A229-00AA003D7352")]
    public interface IObjectWithSite
    {
        [PreserveSig]
        int SetSite([MarshalAs(UnmanagedType.IUnknown)]object site);
        [PreserveSig]
        int GetSite(ref Guid guid, out IntPtr ppvSite);
    }
}
