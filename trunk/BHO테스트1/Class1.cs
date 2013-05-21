using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

using SHDocVw;
using mshtml;
using System.IO;
using Microsoft.Win32;
using System.Runtime.InteropServices;



namespace BHO테스트1
{
    public class Class1
    {
    }


    [
        ComVisible(true),
        InterfaceType(ComInterfaceType.InterfaceIsIUnknown),
        Guid("FC4801A3-2BA9-11CF-A229-00AA003D7352")
    ]
    public interface IObjectWithSite
    {
        [PreserveSig]
        int SetSite([MarshalAs(UnmanagedType.IUnknown)]object site);
        [PreserveSig]
        int GetSite(ref Guid guid, out IntPtr ppvSite);
    }



    [
            ComVisible(true),
            Guid("2159CB25-EF9A-54C1-B43C-E30D1A4A8277"),
            ClassInterface(ClassInterfaceType.None)
    ]
    public class BHO : IObjectWithSite
    {
        private WebBrowser webBrowser;

        public int SetSite(object site)
        {
            if (site != null)
            {
                webBrowser = (WebBrowser)site;
                webBrowser.DocumentComplete +=
                  new DWebBrowserEvents2_DocumentCompleteEventHandler(
                  this.OnDocumentComplete);
            }
            else
            {
                webBrowser.DocumentComplete -=
                  new DWebBrowserEvents2_DocumentCompleteEventHandler(
                  this.OnDocumentComplete);
                webBrowser = null;
            }

            return 0;

        }

        public int GetSite(ref Guid guid, out IntPtr ppvSite)
        {
            IntPtr punk = Marshal.GetIUnknownForObject(webBrowser);
            int hr = Marshal.QueryInterface(punk, ref guid, out ppvSite);
            Marshal.Release(punk);
            return hr;
        }
        

     
        public void OnDocumentComplete(object pDisp, ref object URL)
        {
            HTMLDocument document = (HTMLDocument)webBrowser.Document;


            //HTMLDocument document = (HTMLDocument)webBrowser.Document;

            IHTMLElement head = (IHTMLElement)((IHTMLElementCollection)
                                   document.all.tags("head")).item(null, 0);
            IHTMLScriptElement scriptObject =
              (IHTMLScriptElement)document.createElement("script");
            scriptObject.type = @"text/javascript";
            scriptObject.text = "alert('aaa');";
            ((HTMLHeadElement)head).appendChild((IHTMLDOMNode)scriptObject);
  
            /*
            // If the site or url is null, do not continue
            if (pDisp == null || URL == null) return;
            // Grab the document object off of the WebBrowser control
           
            if (document == null) return;
            // Report the total number of links on the current page
            MessageBox.Show("Total links on this page: " +
            document.links.length.ToString());
             */
        }






        public const string BHO_REGISTRY_KEY_NAME =
   "Software\\Microsoft\\Windows\\" +
   "CurrentVersion\\Explorer\\Browser Helper Objects";

        [ComRegisterFunction]
        public static void RegisterBHO(Type type)
        {
            RegistryKey registryKey =
              Registry.LocalMachine.OpenSubKey(BHO_REGISTRY_KEY_NAME, true);

            if (registryKey == null)
                registryKey = Registry.LocalMachine.CreateSubKey(
                                        BHO_REGISTRY_KEY_NAME);

            string guid = type.GUID.ToString("B");
            RegistryKey ourKey = registryKey.OpenSubKey(guid);

            if (ourKey == null)
            {
                ourKey = registryKey.CreateSubKey(guid);
            }

            ourKey.SetValue("NoExplorer", 1, RegistryValueKind.DWord);

            registryKey.Close();
            ourKey.Close();
        }

        [ComUnregisterFunction]
        public static void UnregisterBHO(Type type)
        {
            RegistryKey registryKey =
              Registry.LocalMachine.OpenSubKey(BHO_REGISTRY_KEY_NAME, true);
            string guid = type.GUID.ToString("B");

            if (registryKey != null)
                registryKey.DeleteSubKey(guid, false);
        }  
    }




}