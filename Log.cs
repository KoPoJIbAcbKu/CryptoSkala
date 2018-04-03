using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace CryptoSkala
{
    public class Log
    {
        public static void Save(string category, string str_to_save, string rootLog, string fileName)
        {
            try
            {               

                DateTime now = DateTime.Now;
                string mDataPath = string.Format("{0}\\{1}\\{2}", now.ToString("yyyy"), now.ToString("MM"), now.ToString("dd"));
                DirectoryInfo proLog = new DirectoryInfo(Path.Combine(rootLog, mDataPath));

                if (!proLog.Exists) proLog.Create();
                
                //string fileName = string.Format("{0}.log", now.ToString("HH-mm"));
                
                string exeption = string.Empty;
                
                string strToSave = string.Format("[{0}] [{1}] [{2}]{3}\r\n",
                    now.ToString("HH:mm:ss"), category.Trim().ToUpper().PadRight(5), str_to_save.Trim(), exeption);

                File.AppendAllText(Path.Combine(proLog.FullName, fileName), strToSave, Encoding.GetEncoding(1251));
            }
            catch
            {

            }
        }

    }
}

