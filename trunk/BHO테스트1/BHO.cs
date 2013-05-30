using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

using SHDocVw;
using mshtml;
using System.IO;
using Microsoft.Win32;
using System.Runtime.InteropServices;
using System.Security.Permissions;
using System.IO.Pipes;

namespace BHO테스트1
{
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
                /*webBrowser.DocumentComplete +=
                  new DWebBrowserEvents2_DocumentCompleteEventHandler(
                  this.OnDocumentComplete);*/
                webBrowser.NavigateComplete2 += new DWebBrowserEvents2_NavigateComplete2EventHandler(this.webBrowser_NavigateComplete2);
            }
            else
            {
                /*webBrowser.DocumentComplete -=
                  new DWebBrowserEvents2_DocumentCompleteEventHandler(
                  this.OnDocumentComplete);*/
                webBrowser.NavigateComplete2 += new DWebBrowserEvents2_NavigateComplete2EventHandler(this.webBrowser_NavigateComplete2);
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

        void webBrowser_NavigateComplete2(object pDisp, ref object URL)
        {
            // If the site or url is null, do not continue
            if (pDisp == null || URL == null) return;

            // Access both the web browser object and the url passed
            // to this event handler
            SHDocVw.WebBrowser browser = (SHDocVw.WebBrowser)pDisp;
            string url = URL.ToString();

            // Grab the document object off of the Web Browser control
            IHTMLDocument2 document = (IHTMLDocument2)webBrowser.Document;
            if (document == null) return;

            if (URL.ToString().Equals("http://www.danawa.com/"))
            {
                int rating = DBConnector.GetUrlRating(url);
                System.Windows.Forms.MessageBox.Show(rating.ToString());
            }

            // Pass the current URL to the broker
            PassUrlToBroker(url);
        }

        public void PassUrlToBroker(string url)
        {
            // Create a new named pipe client object
            NamedPipeClientStream pipeClient = null;

            try
            {

                // Grab a new instance of a named pipe cleint
                // stream, connecting to the same named pipe as the
                // server- BhoPipeName
                pipeClient = new NamedPipeClientStream(
                    ".",
                    "BhoPipeExample",
                    PipeDirection.InOut,
                    PipeOptions.None
                    );

                // Attempt a connection with a 2 second limit
                pipeClient.Connect(1);

                //
                pipeClient.ReadMode = PipeTransmissionMode.Message;

                // Once connected, pass the url to the server
                pipeClient.Write(Encoding.Unicode.GetBytes(url), 0,
                    Encoding.Unicode.GetBytes(url).Length);

                // Wait for the message to complete
                while (!pipeClient.IsMessageComplete) ;

            }
            catch (Exception) { }
            finally
            {
                // Close the pipe client once complete (if exists)
                if (pipeClient != null)
                {
                    pipeClient.Close();
                    pipeClient = null;
                }
            }
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
