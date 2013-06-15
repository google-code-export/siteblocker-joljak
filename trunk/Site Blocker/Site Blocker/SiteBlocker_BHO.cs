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

namespace Site_Blocker
{
    [ComVisible(true),
    Guid("D821DFE1-FE36-44C5-87A0-5BC86AAED996"),
    ClassInterface(ClassInterfaceType.None)]
    public class SiteBlocker_BHO : IObjectWithSite
    {
        private WebBrowser webBrowser;
        //웹브라우저를 컨트롤하기 위한 것
        private String BeforeURL = "";
        //이전에 입력했던 URL, 다시 접근할 때 재확인을 안하기 위해 작성, 근데 잘 작동 안하는 듯. 수정 필요
        public int SetSite(object site)
        {
            // 웹페이지를 설정(그러니까 URL치고 엔터 누르고 페이지를 여는 상황)할때의 처리
            if(site != null) 
            {
                // 제대로 된 페이지를 열었을 때의 처리, a Process to open a right page
                webBrowser = (WebBrowser)site;
                webBrowser.NavigateComplete2 += new DWebBrowserEvents2_NavigateComplete2EventHandler(this.webBrowser_NavigateComplete2);
            }
            else
            {
                webBrowser.NavigateComplete2 += new DWebBrowserEvents2_NavigateComplete2EventHandler(this.webBrowser_NavigateComplete2);
                webBrowser = null;
            }

            return 0;

        }

        public int GetSite(ref Guid guid, out IntPtr ppvSite)
        {
            // 어디 쓰는 건지 솔직히 잘 모르겠음
            IntPtr punk = Marshal.GetIUnknownForObject(webBrowser);
            int hr = Marshal.QueryInterface(punk, ref guid, out ppvSite);
            Marshal.Release(punk);
            return hr;
        }



        public void OnDocumentComplete(object pDisp, ref object URL)
        {
            // HTML등의 파일을 다 열었을 때의 처리, 자바스크립트 인젝션등을 하려면 여기가 적절
            HTMLDocument document = (HTMLDocument)webBrowser.Document;


            //HTMLDocument document = (HTMLDocument)webBrowser.Document;

            /*IHTMLElement head = (IHTMLElement)((IHTMLElementCollection)
                                   document.all.tags("head")).item(null, 0);
            IHTMLScriptElement scriptObject =
              (IHTMLScriptElement)document.createElement("script");
            scriptObject.type = @"text/javascript";
            scriptObject.text = "alert('aaa');";
            ((HTMLHeadElement)head).appendChild((IHTMLDOMNode)scriptObject);*/

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
            // 원래는 페이지를 다 열었을 때, 그러나 이 과정을 거치고 렌더링을 하므로 여기서 처리하는 것도 괜찮은듯..

            // If the site or url is null, do not continue
            if (pDisp == null || URL == null) return;

            // Access both the web browser object and the url passed
            // to this event handler
            SHDocVw.WebBrowser browser = (SHDocVw.WebBrowser)pDisp;
            string url = URL.ToString();

            if (!BeforeURL.Equals(url)) // 똑같은 페이지 또 들어가지 않고 다른데로 들어갔을 때
            {
                /*
                 * ★ 여기가 조금 중요함 ★
                 * 검사하고 점수에 따른 처리 부분
                 */
                BeforeURL = url;
                // Grab the document object off of the Web Browser control
                IHTMLDocument2 document = (IHTMLDocument2)webBrowser.Document;
                if (document == null) return;

                int rating = DBConnector.GetSiteInfo(url);

                if (rating <= 0)
                {
                    // This is Safe Site.
                    // Pass the current URL to the broker
                    PassUrlToBroker(url);
                }
                else if (rating >= 1 && rating <= 25)
                {
                    // This is Reported Site. But Not Blocked Site
                    System.Windows.Forms.MessageBox.Show("Reported");
                    // Pass the current URL to the broker
                    PassUrlToBroker(url);
                }
                else if (rating >= 26 && rating <= 75)
                {
                    // This is Reported Site.
                    System.Windows.Forms.MessageBox.Show("Danger. But Accessable");
                    // Pass the current URL to the broker
                    PassUrlToBroker(url);
                }
                else if (rating >= 76 && rating <= 100)
                {
                    // This is Reported Site.
                    System.Windows.Forms.MessageBox.Show("Danger. Blocked");
                    browser.Stop();
                    document.clear();
                    document.close();
                    browser.Navigate2("about:blank", true);
                }
            }
        }

        public void PassUrlToBroker(string url)
        {
            // URL 혹은 페이지를 받아서 직접적으로 화면에 띄워주는 역할
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

                // 연결 시작, 괄호 안에 숫자 넣으면 그 1초*숫자만큼 느려짐
                pipeClient.Connect();

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
            //BHO 등록
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
            // BHO 삭제
            RegistryKey registryKey =
              Registry.LocalMachine.OpenSubKey(BHO_REGISTRY_KEY_NAME, true);
            string guid = type.GUID.ToString("B");

            if (registryKey != null)
                registryKey.DeleteSubKey(guid, false);
        }
    }
}
