using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Windows.Forms;

using Site_Blocker;

namespace Reporter
{
    public partial class Reporter : Form
    {
        bool ischecked = false;
        static bool firstcheck = true;
        public Reporter()
        {
            InitializeComponent();
        }

        private void checkBox1_CheckedChanged(object sender, EventArgs e)
        {
            if (!ischecked && firstcheck)
            {
                DialogResult dResult = MessageBox.Show("이 항목을 통해 신고를 하시면 SiteBlocker에 이메일 주소를 제공하게 됩니다. 그래도 전송하시겠습니까", "경고", MessageBoxButtons.YesNo);
                switch (dResult)
                {
                    case DialogResult.Yes:
                        firstcheck = false;
                        ischecked = true;
                        this.checkBox1.Checked = true;
                        button1.Enabled = true;
                        break;
                    case DialogResult.No:
                        firstcheck = false;
                        ischecked = false;
                        this.checkBox1.Checked = false;
                        button1.Enabled = false;
                        break;
                }
            }
        }

        private void button1_Click(object sender, EventArgs e)
        {
            String URL = textBox1.Text;
            String Reporter = textBox2.Text;
            bool check = checkBox1.Checked;
            int status = 0;

            if (URL.Length <= 0)
                status = status + 1;
            if (Reporter.Length <= 0)
                status = status + 2;
            switch (status)
            {
                case 1:
                    MessageBox.Show("URL이 입력되지 않았습니다.");
                    break;
                case 2:
                    MessageBox.Show("신고자의 이메일 주소가 입력되지 않았습니다.");
                    break;
                case 3:
                    MessageBox.Show("URL 및 이메일 주소가 입력되지 않았습니다.");
                    break;
                default:
                    DBConnector.ReportSite(URL, Reporter);
                    this.Close();
                    break;
            }
        }

        private void button2_Click(object sender, EventArgs e)
        {
            this.Close();
        }
    }
}
