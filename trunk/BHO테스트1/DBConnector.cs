using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Net;
using System.IO;

namespace BHO테스트1
{
    class DBConnector
    {
        /*
         * 데이터베이스에 접근할 PHP 페이지의 URL
         * 보안을 위해 직접 접근하지는 않음
         * 
         *  == 사용법 ==
         *  점수 가져오기 : GetUrlRating("문자열 형식의 URL);
         *  신고하기 : ReportSite("문자열 형식의 URL","문자열 형식의 이메일");
         */
        const string URL_GET = "http://siteblocker.cloudapp.net/db_get.php";
        const string URL_PUT = "http://siteblocker.cloudapp.net/db_put.php";

        static int GetUrlRating(String Url)
        /*
         * 해당 URL의 신고 점수를 받아옴 다른건 가져올 필요가 없을 것 같아서 뺌
         */
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
                return Int32.Parse(resultPost);
            }
            catch (Exception e)
            {
                Console.WriteLine(e.ToString());
                return -1;
            }
        }
        static Boolean ReportSite(String Url, String Reporter_email)
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
    }
}
