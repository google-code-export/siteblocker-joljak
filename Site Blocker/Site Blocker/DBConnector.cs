using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Net;
using System.IO;
using System.Threading;
using System.Diagnostics;
using SafebrowseV2;

namespace Site_Blocker
{
    public class DBConnector
    {
        /*
         * 데이터베이스에 접근할 PHP 페이지의 URL
         * 보안을 위해 직접 접근하지는 않음
         * 
         *  == 사용법 ==
         *  점수 가져오기 : GetUrlRating("문자열 형식의 URL);
         *  신고하기 : ReportSite("문자열 형식의 URL","문자열 형식의 이메일");
         */
        const string URL_GET = "http://siteblocker.iptime.org/db_get.php";
        const string URL_PUT = "http://siteblocker.iptime.org/db_put.php";

        static Thread T1, T2;
        static Boolean T1_Start, T2_Start;
        static int DBScore; //데이터베이스를 검사해 받아올 점수
        static int GSBScore; //GSB에서 받아올 점수
        // 근데 왜 쓰레드는 리턴형이 무조건 void인지.. C# 이건 좀 짜증남
        static String cacheBaseName = Path.GetTempFileName();
        public static int GetSiteInfo(String Url)
        {
            int score = 0;
            DBScore = 0;
            GSBScore = 0;
            T1_Start = false;
            T2_Start = false;
            try
            {
                T1 = new Thread(new ParameterizedThreadStart(GetFromDB));
                T1.Start(Url);
                T2 = new Thread(new ParameterizedThreadStart(GetFromGSB));
                T2.Start(Url);
                if (!T1_Start && !T2_Start) { }
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
            }
            score = DBScore + GSBScore;
            return score;
        }

        #region GET_URL_SCORE_FROM_ONLINE
        private static void GetFromDB(object Uri)
        {
        /*
         * 데이터베이스에서 URL의 점수를 가져옴
         * 직접 사용하진 않고 위의 메소드에서 호출하는 쓰레드임
         */
            HttpWebRequest wReq;
            Stream PostDataStream;
            Stream respPostStream;
            StreamReader readerPost;
            HttpWebResponse wResp;
            StringBuilder postParams = new StringBuilder();
            String Url = Convert.ToString(Uri);
            T1_Start = true;
            try
            {
                postParams.Append("url=" + Url);

                Encoding encoding = Encoding.UTF8;
                byte[] result = encoding.GetBytes(postParams.ToString());

                wReq = (HttpWebRequest)WebRequest.Create(URL_GET);
                wReq.ContentType = "application/x-www-form-urlencoded; charset=UTF-8";
                wReq.Method = "POST";
                wReq.ContentLength = result.Length;

                PostDataStream = wReq.GetRequestStream();
                PostDataStream.Write(result, 0, result.Length);
                PostDataStream.Close();

                wResp = (HttpWebResponse)wReq.GetResponse();
                respPostStream = wResp.GetResponseStream();
                readerPost = new StreamReader(respPostStream, Encoding.UTF8);
                String resultPost = readerPost.ReadToEnd();
                DBScore = Int32.Parse(resultPost);
                T1_Start = false;
            }
            catch (Exception e)
            {
                Console.WriteLine(e.ToString());
                DBScore = -1;
                T1_Start = false;
            }
        }
        private static void GetFromGSB(object Uri)
        {
            /* Google Safe Browsing API에서 URL의 악성 여부를 탐지
             * 이것역시 당연히 쓰레드로 작동
             */
            T2_Start = true;
            String Url = Convert.ToString(Uri);
            ReputationEngine REngine = new ReputationEngine();
            String apiKey = "";
         
            REngine.Initialize(apiKey, cacheBaseName, 1800);

            if (SafebrowseV2.Reputation.None == REngine.CheckUrl(Url))
            {
                GSBScore = 0;
            }
            else
            {
                GSBScore = 50;
            }
            T2_Start = false;
        }
        #endregion
        #region REPORT_SITE
        public static Boolean ReportSite(String Url, String Reporter_email)
        {
            HttpWebRequest wReq;
            Stream PostDataStream;
            Stream respPostStream;
            StreamReader readerPost;
            HttpWebResponse wResp;
            StringBuilder postParams = new StringBuilder();

            try
            {
                postParams.Append("url=" + Url);
                postParams.Append("&reporter=" + Reporter_email);

                Encoding encoding = Encoding.UTF8;
                byte[] result = encoding.GetBytes(postParams.ToString());

                wReq = (HttpWebRequest)WebRequest.Create(URL_PUT);
                wReq.ContentType = "application/x-www-form-urlencoded; charset=UTF-8";
                wReq.Method = "POST";
                wReq.ContentLength = result.Length;

                PostDataStream = wReq.GetRequestStream();
                PostDataStream.Write(result, 0, result.Length);
                PostDataStream.Close();

                wResp = (HttpWebResponse)wReq.GetResponse();
                respPostStream = wResp.GetResponseStream();
                readerPost = new StreamReader(respPostStream, Encoding.UTF8);
                String resultPost = readerPost.ReadToEnd();
                return true;
            }
            catch (Exception e)
            {
                Console.WriteLine(e.ToString());
                return false;
            }
        }
        #endregion
    }
}
