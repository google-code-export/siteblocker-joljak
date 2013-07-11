using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Drawing;

using SHDocVw;
using mshtml;
using System.IO;
using Microsoft.Win32;
using System.Runtime.InteropServices;
using System.Security.Permissions;
using System.IO.Pipes;
using CustomUIControls;
using System.Text.RegularExpressions;

namespace Site_Blocker
{
    [
            ComVisible(true),
            Guid("2159CB25-EF9A-54C1-B43C-E30D1A4A8277"),
            ClassInterface(ClassInterfaceType.None)
    ]
    public class BHO : IObjectWithSite
    {
        private WebBrowser webBrowser;
        private String BeforeURL = "about:blank";
        private bool check;
        public int SetSite(object site)
        {
            if (site != null)
            {
                check = true;
                webBrowser = (WebBrowser)site;
                // 사용자의 입력을 통한 웹브라우저 메소드(주소창에 입력한다든지 링크를 클릭한다든지 해서 만들어진 것)
                /*webBrowser.DocumentComplete +=
                  new DWebBrowserEvents2_DocumentCompleteEventHandler(
                  this.OnDocumentComplete);*/
                webBrowser.NavigateComplete2 += new DWebBrowserEvents2_NavigateComplete2EventHandler(this.webBrowser_NavigateComplete2);
                webBrowser.DocumentComplete += new DWebBrowserEvents2_DocumentCompleteEventHandler(OnDocumentComplete);
            }
            else
            {
                check = true;
                /*webBrowser.DocumentComplete -=
                  new DWebBrowserEvents2_DocumentCompleteEventHandler(
                  this.OnDocumentComplete);*/
                webBrowser.NavigateComplete2 += new DWebBrowserEvents2_NavigateComplete2EventHandler(this.webBrowser_NavigateComplete2);
                webBrowser.DocumentComplete += new DWebBrowserEvents2_DocumentCompleteEventHandler(OnDocumentComplete);
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
            if (!Convert.ToString(URL).Substring(0, 30).Equals("http://siteblocker.iptime.org/"))
            {
                BeforeURL = webBrowser.LocationURL;
                check = true;
            }
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
            // If the site or url is null, do not continue
            if (pDisp == null || URL == null) return;

            // Access both the web browser object and the url passed
            // to this event handler
            SHDocVw.WebBrowser browser = (SHDocVw.WebBrowser)pDisp;
            // 웹브라우저가 페이지 이동 중에 만드는 웹브라우저 메소드(webBrowser와 browser은 페이지 이동 중에 딱 한 번 일치한다.)
            // 이를 이용해 한번만 검사하도록 변경한게 if (webBrowser.LocationURL.Equals(browser.LocationURL))
            string url = URL.ToString();
            int rating = 0;
            IHTMLDocument2 document = null;
            if (webBrowser.LocationURL.Equals(browser.LocationURL) && check)
                // 현재 이동하는 페이지가 사용자가 URL창에 입력한 주소와 동일한지 체크
                // 혹은 이미 체크했는지 체크(안하면 차단 페이지에 못들어가고 
                // 원래 URL -> 차단 페이지의 버튼 누르면 들어가지는 URL(php 페이지의 burl)의 변수로 들어감 -> 또들어감 -> 또들어감 의 반복
            {
                /* 6월 18~19일 내용 수정
                 * 차단 php 페이지 띄우도록 변경
                 */
                // Grab the document object off of the Web Browser control
                document = (IHTMLDocument2)webBrowser.Document;
                if (document == null) return;

                rating = DBConnector.GetSiteInfo(url);
                if (rating > 0)
                {
                    check = false;
                }
            }
            if (rating <= 0)
            {
                // This is Safe Site.
                // Pass the current URL to the broker
                PassUrlToBroker(url);
            }
            else if (rating >= 1 && rating <= 25)
            {
                // 낮은 점수의 페이지에 접근하면 화면 오른쪽 하단에서 메신저
                // 알림 올라오듯이 만드려고 한거, 근데 작동안함, 하지만 에러가 아예 없어 뭐가 문제인지 파악불가
                // This is Reported Site. But Not Blocked Site
                // Pass the current URL to the broker
                TaskbarNotifier tNotify = new TaskbarNotifier();
                tNotify.SetBackgroundBitmap("popup.bmp", Color.FromArgb(0, 0, 0));
                tNotify.SetCloseBitmap("close.bmp", Color.FromArgb(0, 0, 0), new Point(127, 8));
                tNotify.TitleRectangle = new Rectangle(40, 9, 70, 25);
                tNotify.ContentRectangle = new Rectangle(8, 41, 133, 68);
                tNotify.TitleClick += new EventHandler(TitleClick);
                tNotify.ContentClick += new EventHandler(ContentClick);
                tNotify.CloseClick += new EventHandler(CloseClick);
                tNotify.Show("경고", "신고된 페이지입니다. 주의하여 사용해주세요", 100, 300, 100);
                // 수정이 필요하면 이 위에까지 잘라내고 새로 넣어도 무방함. 아래는 페이지를 띄워주는 코드이므로 안됨
                PassUrlToBroker(url);
            }
            else if (rating >= 26 && rating <= 75)
            {
                // This is Reported Site.
                // Move to weak Blocked page
                // 점수가 그냥 높은 수준일 때 차단 페이지로 이동.
                // webBrowser.LocationURL : URL을 직접 입력, 혹은 Navigate2로 이동할 때 기록되는 페이지
                // BeforeURL : 이전 주소
                browser.Stop();
                browser.Navigate2("http://siteblocker.iptime.org/blocked.php?lvl=0&url=" + webBrowser.LocationURL + "&burl=" + BeforeURL, true);
            }
            else if (rating >= 76 && rating <= 100)
            {
                // This is Reported Site.
                // Move to String Blocked Page
                browser.Stop();
                browser.Navigate2("http://siteblocker.iptime.org/blocked.php?lvl=1&url=" + webBrowser.LocationURL + "&burl=" + BeforeURL, true);
            }
            rating = 0;
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
                pipeClient.Connect(0);

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

        // 알림 창 부분. 근데 작동 안하니 뭐..
        #region 노티바에 대한 이벤트 핸들러
        void CloseClick(object obj, EventArgs ea)
        {
        }

        void TitleClick(object obj, EventArgs ea)
        {
        }

        void ContentClick(object obj, EventArgs ea)
        {
        }
        #endregion
    }
}