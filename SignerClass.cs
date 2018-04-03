using System;
using System.Collections.Generic;
using System.Text;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Xml;
using System.IO;
using CryptoPro.Sharpei.Xml;
using CryptoPro.Sharpei;
using System.Security.Cryptography.Xml;
using System.Runtime.Serialization.Formatters.Binary;
using System.Collections;
using System.Xml.Linq;
using System.Security.Cryptography.Pkcs;

namespace CryptoSkala
{
    public class SignedClass
    {
        /// <summary>
        /// сертификат для подписывания файлов
        /// </summary>
        private X509Certificate2 Certificate;
        /// <summary>
        /// сертификат для шифрования
        /// </summary>
        private X509Certificate2 EncryptCertificate;
        /// <summary>
        /// сертификат для расшифровки
        /// </summary>
        private X509Certificate2 DecryptCertificate;
        /// <summary>
        /// xml - файл
        /// </summary>
        private XmlDocument doc;
        /// <summary>
        /// Путь до Лог-файла
        /// </summary>
        public string SignLog { get; set; }
        private string filenameLog { get; set; }

        /// <summary>
        /// Подписать файл. Добавить реквест ид
        /// </summary>
        /// <param name="filename">путь до файла, который хотим подписать</param>
        /// <param name="request">номер запроса</param>
        /// <param name="sign">нужна ли подпись</param>
        /// <returns></returns>
        public bool SignXml(string filename, string request, bool sign)
        {
            try
            {
                Log.Save("подписывание файла", filename + " " + request, SignLog, filenameLog);
                if (!XMLLoad(filename)) return false;
                if (filename.IndexOf("MigCase") != -1 || filename.IndexOf("UnregMigCase") != -1)
                    if (!AddRequestId(request)) return false;

                if (sign)
                if (!SignXmlFile()) return false;
                return true;
            }
            catch
            {
                return false;
            }
        }

        public bool SignXml(bool isRequest, XmlDocument document, string request, bool sign)
        {
            try
            {
                Log.Save("подписывание файла", request, SignLog, filenameLog);
                doc = document;
                if (isRequest)
                    if (!AddRequestId(request)) return false;
                if (sign)
                    if (!SignXmlFile()) return false;
                return true;
            }
            catch
            {
                return false;
            }
        }

        public bool SignXml(bool isRequest, XDocument document, string request, bool sign)
        {
            try
            {
                Log.Save("подписывание файла", request, SignLog, filenameLog);
                doc = GetXmlDocument(document);
                if (isRequest)
                    if (!AddRequestId(request)) return false;
                if (sign)
                    if (!SignXmlFile()) return false;
                return true;
            }
            catch
            {
                return false;
            }
        }

        public Guid? SignXmlFile(XDocument document, DirectoryInfo dir)
        {
            try
            {
                Encoding unicode = Encoding.Unicode;
                ContentInfo contentInfo = new ContentInfo(unicode.GetBytes(document.ToString()));
                SignedCms signedCms = new SignedCms(contentInfo, true);
                CmsSigner cmsSigner = new CmsSigner(EncryptCertificate);
                signedCms.ComputeSignature(cmsSigner);
                Guid guid = Guid.NewGuid();
                File.WriteAllBytes(Path.Combine(dir.FullName, guid.ToString("N").ToLower() + ".bin"), signedCms.Encode());
                return guid;
            }
            catch (Exception)
            {
                return null;
            }
        }

        public byte[] SignXmlFile(byte[] text)
        {
            try
            {
                Encoding unicode = Encoding.Unicode;
                ContentInfo contentInfo = new ContentInfo(text);
                SignedCms signedCms = new SignedCms(contentInfo, true);
                CmsSigner cmsSigner = new CmsSigner(EncryptCertificate);
                signedCms.ComputeSignature(cmsSigner);
                
                return signedCms.Encode();
            }
            catch (Exception)
            {
                return null;
            }
        }

        public Guid? EncryptZipFile(string filename, DirectoryInfo dir)
        {
            try
            {
                Encoding unicode = Encoding.Unicode;
                ContentInfo contentInfo = new ContentInfo(File.ReadAllBytes(filename));
                EnvelopedCms enveloped = new EnvelopedCms(contentInfo);                
                enveloped.Certificates.Add(EncryptCertificate);
                CmsRecipientCollection collection = new CmsRecipientCollection();
                CmsRecipient recepient = new CmsRecipient(EncryptCertificate);
                collection.Add(recepient);
                recepient = new CmsRecipient(DecryptCertificate);
                collection.Add(recepient);
                enveloped.Encrypt(collection);
                Guid guid = Guid.NewGuid();
                File.WriteAllBytes(Path.Combine(dir.FullName, guid.ToString("N").ToLower() + ".bin"), enveloped.Encode());
                return guid;
            }
            catch (Exception)
            {
                return null;
            }
        }

        public Byte[] DecryptMsg(byte[] encodedEnvelopedCms)
        {
            var s = "";
            try
            {
                EnvelopedCms envelopedCms = new EnvelopedCms();
                envelopedCms.Decode(encodedEnvelopedCms);

                /*Console.Write("Decrypting Data ... ");
                X509Certificate2Collection certs = new X509Certificate2Collection();
                certs.Add(Certificate);
                envelopedCms.Decrypt(certs);*/

                X509Store store;
                store = new X509Store("My", StoreLocation.CurrentUser);
                store.Open(OpenFlags.OpenExistingOnly | OpenFlags.ReadOnly);
                envelopedCms.Decrypt(envelopedCms.RecipientInfos[0]);
                Console.WriteLine("Done.");
                return envelopedCms.ContentInfo.Content;
            }
            catch (Exception ex)
            {
                s = ex.GetType().ToString();
                throw;
            }            
        }

        public byte[] DecryptZipFile(byte[] bytes)
        {
            try
            {
                Encoding unicode = Encoding.Unicode;
                //ContentInfo contentInfo = new ContentInfo(bytes);
                EnvelopedCms enveloped = new EnvelopedCms();
                enveloped.Decode(bytes);

                enveloped.Decrypt(enveloped.RecipientInfos[1]);
                //enveloped.Certificates.Add(Certificate);
                //enveloped.Certificates.Add(EncryptCertificate);
                return enveloped.Encode();
            }
            catch (Exception)
            {
                return null;
            }
        }

        public byte[] EncryptZipFile(byte[] bytes)
        {
            try
            {
                Encoding unicode = Encoding.Unicode;
                ContentInfo contentInfo = new ContentInfo(bytes);
                EnvelopedCms enveloped = new EnvelopedCms(contentInfo);
                enveloped.Certificates.Add(EncryptCertificate);
                CmsRecipientCollection collection = new CmsRecipientCollection();
                CmsRecipient recepient = new CmsRecipient(EncryptCertificate);
                collection.Add(recepient);
                recepient = new CmsRecipient(DecryptCertificate);
                collection.Add(recepient);
                enveloped.Encrypt(collection);
                return enveloped.Encode();
            }
            catch (Exception)
            {
                return null;
            }
        }

        public static XmlDocument GetXmlDocument(XDocument document)
        {
            using (XmlReader xmlReader = document.CreateReader())
            {
                XmlDocument xmlDoc = new XmlDocument();
                xmlDoc.Load(xmlReader);
                if (document.Declaration != null)
                {
                    XmlDeclaration dec = xmlDoc.CreateXmlDeclaration(document.Declaration.Version,
                        document.Declaration.Encoding, document.Declaration.Standalone);
                    xmlDoc.InsertBefore(dec, xmlDoc.FirstChild);
                }
                return xmlDoc;
            }
        }

        /// <summary>
        /// конструктор для шифрования с подгрузкой файла
        /// </summary>
        /// <param name="encNum">номер сертификата для шифрования</param>
        /// <param name="decNum">номер сертификата для дешифрования</param>
        /// <param name="filename">путь до файла</param>
        public SignedClass(string encNum, string decNum, string filename, string Log, string fnameLog)
        {
            SignLog = Log;
            filenameLog = fnameLog;
            GetCertificateUser(encNum, "encrypt");
            GetCertificateMachine(encNum, "encrypt");
            GetCertificateUser(encNum, "encrypt");
            GetCertificateMachine(encNum, "encrypt");
            GetCertificateUser(decNum, "decrypt");
            GetCertificateMachine(decNum, "decrypt");

            if ((filename != null) && (filename != ""))
            XMLLoad(filename);
        }
        
        public SignedClass()
        {

        }

        public SignedClass(string Log, string NameF)
        {
            SignLog = Log;
            filenameLog = NameF;
        }

        public void setEncSert(X509Certificate2 cert)
        {
            EncryptCertificate = cert;
            DecryptCertificate = cert;
        }

        public void setEncSert(byte[] cert)
        {
            EncryptCertificate = new X509Certificate2(cert);
        }

        /// <summary>
        /// полный конструктор
        /// </summary>
        /// <param name="certNum">номер сертификата для подписи</param>
        /// <param name="encNum">номер сертификата для шифрования</param>
        /// <param name="decNum">номер сертификата для дешифрования</param>
        /// <param name="filename">путь до файла</param>
        public SignedClass(string certNum, string encNum, string decNum, string filename, string Log, string fnameLog)
        {
            SignLog = Log;
            filenameLog = fnameLog;
            GetCertificateUser(encNum, "encrypt");
            GetCertificateMachine(encNum, "encrypt");

            GetCertificateUser(encNum, "encrypt");
            GetCertificateMachine(encNum, "encrypt");
            GetCertificateUser(decNum, "decrypt");
            GetCertificateMachine(decNum, "decrypt");
            GetCertificateUser(certNum, "sign");
            GetCertificateMachine(certNum, "sign");

            if ((filename != null) && (filename != ""))
                XMLLoad(filename);
        }
        
        public DateTime GetDateCert()
        {
            try
            {
                if (Certificate != null)
                {
                    if (!Certificate.HasPrivateKey) throw new Exception("Сертификат не содержит закрытый ключ, переустановите сертификат");

                    if (Certificate.NotAfter < DateTime.Now) throw new Exception("Сертификат устарел, необходимо получить новый сертификат у УЦ");
                    else return Certificate.NotAfter;
                }
                else throw new Exception("Сертификат не найден");
            }
            catch (Exception)
            {
                throw;
            }
        }

        /// <summary>
        /// конструктор для подписи файла с его подгрузкой
        /// </summary>
        /// <param name="certNum">номер сертификата для подписи</param>
        /// <param name="filename">название файла</param>
        public SignedClass(string certNum, string filename, string Log, string fnameLog)
        {
            SignLog = Log;
            filenameLog = fnameLog;
            GetCertificateUser(certNum, "sign");
            GetCertificateUser(certNum, "sign");
            GetCertificateMachine(certNum, "sign");

            int i = 0;
            if (Certificate == null)
                i = 1;

            if ((filename != null) && (filename != ""))
                XMLLoad(filename);
        }
        
        /// <summary>
        /// подписывание ответов от уфмс
        /// </summary>
        /// <returns></returns>
        public bool SignXml()
        {
            try
            {
                Log.Save("подписывание файла", doc.Name, SignLog, filenameLog);

                if (AddSignInfo())
                    if (!SignXmlFile()) return false;
                return true;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// добавление информации о подписи в ответах от фмс
        /// </summary>
        /// <param name="certInfo"></param>
        /// <returns></returns>
        private bool AddSignInfo()
        {
            try
            {
                string certInfo = Certificate.SubjectName.Name;
                Log.Save("подписывание файла", doc.Name, SignLog, filenameLog);
                doc.PreserveWhitespace = false;

                XmlNode SignatureAttr = doc.CreateElement("SignatureAttr", "http://supersh.ru/signature-attr");

                string cn = certInfo;
                cn = cn.Substring(cn.IndexOf(", CN=") + 3);
                cn = cn.Substring(0, cn.IndexOf(','));

                XmlNode CN = doc.CreateElement("CN");
                CN.InnerText = cn;
                SignatureAttr.AppendChild(CN);

                XmlNode Date = doc.CreateElement("Date");
                Date.InnerText = File.GetCreationTime(doc.BaseURI.Substring(8)).ToString();
                SignatureAttr.AppendChild(Date);

                XmlNode Org = doc.CreateElement("Org");
                string o = certInfo;
                o = o.Substring(o.IndexOf(", O=") + 3);
                o = o.Substring(0, o.IndexOf(','));
                Org.InnerText = o;
                SignatureAttr.AppendChild(Org);

                doc.LastChild.AppendChild(SignatureAttr);

                Log.Save("Поиск тэга тип ответа", "", SignLog, filenameLog);
                if (doc.GetElementsByTagName("entityType").Count == 0)
                {
                    Log.Save("Тэг - тип ответа", "не найден", SignLog, filenameLog);
                    XmlNode entity = doc.CreateElement("ns3", "entityType", "http://umms.fms.gov.ru/replication/response");
                    entity.InnerText = "MigCase";
                    doc.LastChild.AppendChild(entity);
                    Log.Save("Тэг - тип ответа", "добавлен", SignLog, filenameLog);
                }
                else
                    Log.Save("Тэг - тип ответа", "найден", SignLog, filenameLog);
                
                Log.Save("подписывание файла", doc.Name, SignLog, filenameLog);
                return true;
            }
            catch
            { }
            return false;
        }

        /// <summary>
        /// Информация о сертификатах
        /// </summary>
        /// <returns></returns>
        public string InfoCert()
        {
            string result = "";

            try
            {
                if (Certificate!= null)
                    result += Certificate.SerialNumber;
                else
                    result += "не определён";
                result += "#";
                if (Certificate != null)
                    result += EncryptCertificate.SerialNumber;
                else
                    result += "не определён";
                result += "#";
                if (Certificate != null)
                    result += DecryptCertificate.SerialNumber;
                else
                    result += "не определён";
            }
            catch (Exception ex)
            {
                return ex.StackTrace + ex.Message;
            }
            return result;
        }

        /// <summary>
        /// зашифровать файл
        /// </summary>
        /// <param name="filename">путь до файла</param>
        /// <returns></returns>
        public bool EncryptXML(string filename)
        {
            try
            {
                if (!XMLLoad(filename)) return false;
                return Encrypt();
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// зашифровать файл, подгруженный в память
        /// </summary>
        /// <returns></returns>
        public bool EncryptXML()
        {
            try
            {
                return Encrypt();
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// расшифровать файл
        /// </summary>
        /// <param name="filename">путь до файла</param>
        /// <returns></returns>
        public bool DecryptXML(string filename)
        {
            try
            {
                if (!XMLLoad(filename)) return false;
                return Decrypt();
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Убрать подпись
        /// </summary>
        /// <param name="filename">путь до файла</param>
        /// <returns></returns>
        public bool ClearSigner() 
        {
            try
            {
                return ClearSign();
            }
            catch
            {
                return false;
            }
        }
        
        /// <summary>
        /// Убрать подпись
        /// </summary>
        /// <param name="filename">путь до файла</param>
        /// <returns></returns>
        public bool ClearSigner(XmlDocument docX)
        {
            try
            {
                return ClearSign(docX);
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// расшифровать файл, подгруженный в память
        /// </summary>
        /// <returns></returns>
        public bool DecryptXML()
        {
            try
            {                
                return Decrypt();
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// добавить реквест ид
        /// </summary>
        /// <param name="id">идентификатор запроса</param>
        /// <returns></returns>
        private bool AddRequestId(string id)
        {
            try
            {
                //if (doc)
                XmlElement RequestID = doc.CreateElement("requestId", "http://umms.fms.gov.ru/replication/core");
                RequestID.InnerText = id;

                doc.LastChild.InsertBefore(RequestID, doc.LastChild.FirstChild.NextSibling);
                Log.Save("добавление к файлу информации. requestId", "добавлен номер " + id, SignLog, filenameLog);
                return true;
            }
            catch (Exception ex)
            {
                Log.Save("добавление к файлу информации. requestId", ex.StackTrace + ex.Message, SignLog, filenameLog);
                return false;
            }
        }

        /// <summary>
        /// подгрузка файла в память
        /// </summary>
        /// <param name="FileName">путь до файла</param>
        /// <returns></returns>
        public bool XMLLoad(string FileName)
        {
            try
            {
                Log.Save("загрузка файла xml в память", FileName, SignLog, filenameLog);
                doc = new XmlDocument();
                doc.PreserveWhitespace = false;
                // Читаем документ из файла.
                using (XmlTextReader reader = new XmlTextReader(FileName))
                {
                    doc.Load(reader);
                }
                Log.Save("загрузка файла xml в память", "файл загружен", SignLog, filenameLog);
                return true;
            }
            catch (Exception ex)
            {
                Log.Save("загрузка файла xml в память", ex.StackTrace + ex.Message, SignLog, filenameLog);
                return false;
            }
        }

        /// <summary>
        /// загрузить сетификат
        /// </summary>
        /// <param name="Number">серия сертификата</param>
        /// <param name="typeCert">тип сертификата</param>
        /// <param name="stor">хранилище сертификата { user | machine }</param>
        /// <returns></returns>
        public bool GetCertificateUser(string Number, string typeCert)
        {
            try
            {
                if (Number == null || Number == "") return false;
                Log.Save("загрузка сертификата", "Номер: " + Number + "Тип: " + typeCert, SignLog, filenameLog);
                X509Store store;
                store = new X509Store("My", StoreLocation.CurrentUser);
                store.Open(OpenFlags.OpenExistingOnly | OpenFlags.ReadOnly);
                X509Certificate2Collection found = store.Certificates.Find(X509FindType.FindBySerialNumber, Number, false);
                //X509Certificate2Collection found = store.Certificates.Find(X509FindType.FindBySubjectName, Number, false);
                
                if (found.Count == 0)
                {
                    Log.Save("загрузка сертификата", "Сертификат не найден", SignLog, filenameLog);
                    return false;
                    /*found = store.Certificates.Find(X509FindType.FindBySerialNumber, Number, false);
                    if (found.Count == 0)
                    {
                        Log.Save("загрузка сертификата", "Сертификат не найден", SignLog, filenameLog);
                        return false;
                    }
                    if (found.Count > 1)
                    {
                        Log.Save("загрузка сертификата", "Найдено больше одного сертификата", SignLog, filenameLog);
                        return false;
                    }
                    if (typeCert == "sign")
                        Certificate = found[0];
                    else if (typeCert == "encrypt")
                        EncryptCertificate = found[0];
                    else if (typeCert == "decrypt")
                        DecryptCertificate = found[0];
                    else return false;
                    return true;*/
                }
                if (found.Count > 1)
                {
                    Log.Save("загрузка сертификата", "Найдено больше одного сертификата", SignLog, filenameLog);
                    return false;
                }
                else 
                {
                    Log.Save("загрузка сертификата", "Сертификат найден", SignLog, filenameLog);
                }
                if (typeCert == "sign")
                    Certificate = found[0];
                else if (typeCert == "encrypt")
                    EncryptCertificate = found[0];
                else if (typeCert == "decrypt")
                    DecryptCertificate = found[0];
                else return false;

                return true;
            }
            catch (Exception ex)
            {
                throw;
            }
        }

        public X509Certificate2Collection GetCertificates()
        {
            try
            {
                X509Store store;

                store = new X509Store("My", StoreLocation.CurrentUser);
                store.Open(OpenFlags.OpenExistingOnly | OpenFlags.ReadOnly);

                var result = store.Certificates;
                return result;
            }
            catch (Exception ex)
            {
                throw;
            }
        }

        /// <summary>
        /// загрузить сетификат
        /// </summary>
        /// <param name="Number">серия сертификата</param>
        /// <param name="typeCert">тип сертификата</param>
        /// <param name="stor">хранилище сертификата { user | machine }</param>
        /// <returns></returns>
        public bool GetCertificateMachine(string Number, string typeCert)
        {
            try
            {
                if (Number == null || Number == "") return false;
                Log.Save("загрузка сертификата", "Номер: " + Number + "Тип: " + typeCert, SignLog, filenameLog);
                X509Store store;
                store = new X509Store("My", StoreLocation.LocalMachine);
                store.Open(OpenFlags.OpenExistingOnly | OpenFlags.ReadOnly);

                X509Certificate2Collection found = store.Certificates.Find(X509FindType.FindBySerialNumber, Number.ToUpper(), false);
                
                if (found.Count == 0)
                {
                    Log.Save("загрузка сертификата", "Сертификат не найден", SignLog, filenameLog);
                    return false;
                }
                if (found.Count > 1)
                {
                    Log.Save("загрузка сертификата", "Найдено больше одного сертификата", SignLog, filenameLog);
                    return false;
                }
                else
                {
                    Log.Save("загрузка сертификата", "Сертификат найден " + typeCert + " " + Number, SignLog, filenameLog);
                }
                if (typeCert == "sign")
                    Certificate = found[0];
                else if (typeCert == "encrypt")
                    EncryptCertificate = found[0];
                else if (typeCert == "decrypt")
                    DecryptCertificate = found[0];
                else return false;

                return true;
            }
            catch (Exception ex)
            {
                throw;
            }
        }

        public void SaveAllCerts()
        {
            X509Store store;
            store = new X509Store("My", StoreLocation.LocalMachine);
            store.Open(OpenFlags.OpenExistingOnly | OpenFlags.ReadOnly);
            foreach (var cert in store.Certificates)
            {
                //var result = cert.Export(X509ContentType.Pfx);
                if (cert.HasPrivateKey)
                {
                    byte[] certData = cert.Export(X509ContentType.Pkcs12);
                    try
                    {
                        var name = cert.SubjectName.Name;
                        if (name.StartsWith("SERIALNUMBER=4201"))
                        {
                            CspParameters Params = new CspParameters();
                            Params.KeyContainerName = "KeyContainer";
                            Gost3410CryptoServiceProvider GOST = new Gost3410CryptoServiceProvider();
                            //byte[] certData2 = GOST.ExportCspBlob(true);
                            
                            byte[] certData2 = cert.Export(X509ContentType.Pkcs12);
                            File.WriteAllBytes(Path.Combine("C:/100", "123" + ".pfx"), certData2);
                        }
                    }
                    catch (Exception)
                    {
                        
                    }

                    X509Certificate newCert = new X509Certificate(certData);

                    // Get the value.
                    string resultsTrue = newCert.ToString(true);

                    // Display the value to the console.
                    Console.WriteLine(resultsTrue);

                    // Get the value.
                    string resultsFalse = newCert.ToString(false);

                    // Display the value to the console.
                    Console.WriteLine(resultsFalse);
                }
            }
        }

        /// <summary>
        /// сохранить файл с помощью потока
        /// </summary>
        /// <param name="fileName">путь до файла</param>
        /// <returns></returns>
        public bool Save(string fileName)
        {
            try
            {
                if (doc.InnerText == "<?xml version=\"1.0\" encoding=\"utf-8\"?>")
                    return false;
                using (XmlTextWriter xmltw = new XmlTextWriter(fileName, new UTF8Encoding(false)))
                {
                    xmltw.WriteStartDocument();
                    doc.WriteTo(xmltw);
                }
                
                return true;
            }
            catch (Exception ex)
            {
                return false;
            }
        }

        /// <summary>
        /// сохранить файл
        /// </summary>
        /// <param name="fileName"></param>
        /// <returns></returns>
        public bool DocSave(string fileName)
        {
            try
            {
                doc.Save(fileName);

                return true;
            }
            catch (Exception ex)
            {
                return false;
            }
        }

        /// <summary>
        /// сохранить файл
        /// </summary>
        /// <param name="fileName"></param>
        /// <returns></returns>
        public bool UnLoad()
        {
            try
            {
                doc = null;

                return true;
            }
            catch (Exception ex)
            {
                return false;
            }
        }

        /// <summary>
        /// подписать файл
        /// </summary>
        /// <param name="Key">закрытый ключ</param>
        /// <param name="Certificate">сертификат</param>
        /// <returns></returns>
        private bool SignXmlFile()
        {
            try
            {
                Log.Save("подпись файла", "с помощью сертификата " + Certificate.SubjectName.Name, SignLog, filenameLog);
                SignedXml signedXml = new SignedXml(doc);
                signedXml.SigningKey = Certificate.PrivateKey;
                signedXml.SignedInfo.SignatureMethod = CPSignedXml.XmlDsigGost3410UrlObsolete;
                Reference reference = new Reference();
                reference.Uri = "";
                reference.DigestMethod = CPSignedXml.XmlDsigGost3411UrlObsolete;
                XmlDsigEnvelopedSignatureTransform env = new XmlDsigEnvelopedSignatureTransform();
                reference.AddTransform(env);
                signedXml.AddReference(reference);
                KeyInfo keyInfo = new KeyInfo();
                KeyInfoX509Data kdata = new KeyInfoX509Data();
                X509IssuerSerial xserial;
                var Issuer = "";
                var OGRN = "OID.1.2.643.100.1=#120D";
                var KPP = "OID.1.2.643.3.131.1.1=#120C";
                var INN = "OID.1.2.643.3.131.1.1=#120C";
                var EMAIL = "EMAILADDRESS=";
                var str = Certificate.IssuerName.Name;
                var str2 = "";
                #region ИНН
                if (str.IndexOf("ИНН=") != -1)
                {
                    str2 = str.Substring(str.IndexOf("E=") + 2);
                    try
                    {
                        str2 = str2.Substring(0, str2.IndexOf(','));
                    }
                    catch
                    { }
                    Issuer = str.Replace("E=" + str2, EMAIL + str2);

                    str = Certificate.IssuerName.Name;
                    str2 = str.Substring(str.IndexOf("ИНН=") + 4);
                    try
                    {
                        str2 = str2.Substring(0, str2.IndexOf(','));
                    }
                    catch
                    { }
                    var result = "";
                    foreach (var c in str2)
                    {
                        result += "3" + c;
                    }
                    Issuer = Issuer.Replace("ИНН=" + str2, INN + result);
                }
                #endregion

                #region КПП
                str = Certificate.IssuerName.Name;
                if (str.IndexOf("КПП=") != -1)
                {
                    str2 = str.Substring(str.IndexOf("КПП=") + 4);
                    try
                    {
                        str2 = str2.Substring(0, str2.IndexOf(','));
                    }
                    catch
                    { }
                    var result2 = "";
                    foreach (var c in str2)
                    {
                        result2 += "3" + c;
                    }
                    Issuer = Issuer.Replace("КПП=" + str2, KPP + result2);
                }
                #endregion

                #region ОГРН
                str = Certificate.IssuerName.Name;
                if (str.IndexOf("ОГРН=") != -1)
                {
                    str2 = str.Substring(str.IndexOf("ОГРН=") + 5);
                    try
                    {
                        str2 = str2.Substring(0, str2.IndexOf(','));
                    }
                    catch
                    { }
                    var result3 = "";
                    foreach (var c in str2)
                    {
                        result3 += "3" + c;
                    }
                    Issuer = Issuer.Replace("ОГРН=" + str2, OGRN + result3);
                }
                #endregion

                #region O
                str = Certificate.IssuerName.Name;
                Issuer = Issuer.Replace("O=\"ЗАО \"\"УДОСТОВЕРЯЮЩИЙ ЦЕНТР\"\"\"", "O=ЗАО \"УДОСТОВЕРЯЮЩИЙ ЦЕНТР\"");
                Issuer = Issuer.Replace("O=\"ООО \"\"ИТК\"\"\"", "O=ООО \"ИТК\"");
                Issuer = Issuer.Replace("O=\"ЗАО \"\"Калуга Астрал\"\"\"", "O=ЗАО \"Калуга Астрал\"");
                Issuer = Issuer.Replace("O=\"ЗАО \"\"КАЛУГА АСТРАЛ\"\"\"", "O=ЗАО \"КАЛУГА АСТРАЛ\"");
                Issuer = Issuer.Replace("O=\"ООО \"\"Удостоверяющий Центр Траст\"\"\"", "O=ООО \"Удостоверяющий Центр Траст\"");
                Issuer = Issuer.Replace("O=\"ЗАО \"\"ПФ \"\"СКБ Контур\"\"\"", "O=ООО \"ПФ \"СКБ Контур\"");

                //Issuer = Issuer.Replace("O=ООО УЦ Траст", "O=ООО \"УЦ Траст\"");
                //Issuer = Issuer.Replace("CN=ООО УЦ Траст", "CN=ООО «УЦ Траст»"); 
                //Issuer = Issuer.Replace("O=ООО УЦ Траст", "O=ООО \"УЦ Траст\""); 

                Issuer = Issuer.Replace("CN=\"УЦ1 ЗАО \"\"ПФ \"\"СКБ Контур\"\"\"", "CN=УЦ1 ЗАО \"ПФ \"СКБ Контур\"");
                Issuer = Issuer.Replace("CN=\"ЗАО \"\"КАЛУГА АСТРАЛ\"\"\"", "CN=ЗАО \"КАЛУГА АСТРАЛ\"");

                //Issuer = Issuer.Replace("\"\"", "&quot;");
                //Issuer = Issuer.Replace("\"", "");
                //Issuer = Issuer.Replace("&quot;", "\"");

                if (str.IndexOf(" O=") != -1)
                {
                    /*str2 = str.Substring(str.IndexOf(" O=") + 3);
                    try
                    {
                        str2 = str2.Substring(0, str2.IndexOf(','));
                    }
                    catch
                    { }
                    if (str2.IndexOf("\"") != -1)
                    {
                        var result3 = "";
                        var i = 0;
                        foreach (var c in str2)
                        {
                            if (i == 0 || i == str2.Length - 1 || c != '\"')
                                result3 += c;
                            else
                                result3 += "\\" + "\"";
                            i++;
                        }
                        Issuer = Issuer.Replace(" O=" + str2, " O=" + result3);
                    }*/
                }
                #endregion
                xserial.IssuerName = Issuer;
                //xserial.IssuerName = Issuer.Replace("\"", "");
                xserial.SerialNumber = Certificate.SerialNumber;

                kdata.AddIssuerSerial(xserial.IssuerName, xserial.SerialNumber);

                keyInfo.AddClause(kdata);
                signedXml.KeyInfo = keyInfo;
                signedXml.ComputeSignature();
                
                XmlElement xmlDigitalSignature = signedXml.GetXml();
                doc.FirstChild.NextSibling.InsertAfter(xmlDigitalSignature, doc.FirstChild.NextSibling.FirstChild);
                if (doc.FirstChild is XmlDeclaration)
                {
                    doc.RemoveChild(doc.FirstChild);
                }
                Log.Save("подпись файла", "файл подписан", SignLog, filenameLog);
                return true;
            }
            catch (Exception ex)
            {
                while (ex != null)
                {
                    Log.Save("подпись файла", "ошибка " + ex.StackTrace + ex.Message, SignLog, filenameLog);
                    ex = ex.InnerException;
                }
                return false;
            }
        }

        /// <summary>
        /// Шифрование файла
        /// </summary>
        /// <returns></returns>
        private bool Encrypt()
        {
            try
            {
                Log.Save("шифрование", "файл шифруется", SignLog, filenameLog);
                doc.PreserveWhitespace = true;
                // Ищем заданный элемент для заширования.
                Log.Save("шифрование файла", doc.FirstChild.Name, SignLog, filenameLog);
                XmlElement elementToEncrypt;
                if (doc.FirstChild.Name != "xml")
                    elementToEncrypt = (XmlElement)doc.FirstChild;
                else elementToEncrypt = (XmlElement)doc.FirstChild.NextSibling;
                if (elementToEncrypt == null)
                    throw new XmlException("Узел не найден");

                // Создаем объект EncryptedData и заполняем его
                // необходимой информацией.
                EncryptedData edElement = new EncryptedData();
                edElement.Type = EncryptedXml.XmlEncElementUrl;

                // Созданный элемент помечаем EncryptedElement1
                edElement.Id = "EncryptedElement1";

                // Заполняем алгоритм зашифрования данных. 
                // Он будет использован при расшифровании.
                edElement.EncryptionMethod = new EncryptionMethod(CPEncryptedXml.XmlEncGost28147Url);

                // Создаем новую ссылку на ключ.
                edElement.KeyInfo = new KeyInfo();

                // Создаем случайный симметричный ключ.
                // В целях безопасности удаляем ключ из памяти после использования.
                using (Gost28147CryptoServiceProvider sessionKey = new Gost28147CryptoServiceProvider())
                {
                    // Создаем объект класса EncryptedXml
                    EncryptedXml eXml = new EncryptedXml();

                    // Зашифроваем узел на симметричном ключе.
                    byte[] encryptedElement = eXml.EncryptData(elementToEncrypt, sessionKey, false);

                    // Создаем элемент DataReference для KeyInfo.
                    // Эта необязательная операция позволяет указать
                    // какие данные используют данный ключ.
                    // XML документ может содержвать несколько
                    // элементов EncryptedData с различными ключами.
                    DataReference dRef = new DataReference();

                    // Указываем URI EncryptedData.
                    // Для этого используем ранее проставленную ссылку
                    // EncryptionElementID
                    dRef.Uri = "#EncryptedElement1";

                    // Для каждого получателя
                    //foreach (X509Certificate2 cert in recipient)
                    {
                        // Зашифровываем сессионный ключ и добавляем эти зашифрованные данные
                        // к узлу EncryptedKey.
                        EncryptedKey ek = new EncryptedKey();
                        byte[] encryptedKey = CPEncryptedXml.EncryptKey(
                            sessionKey, (Gost3410)EncryptCertificate.PublicKey.Key);

                        ek.CipherData = new CipherData(encryptedKey);
                        ek.EncryptionMethod = new EncryptionMethod(
                            CPEncryptedXml.XmlEncGostCryptoProKeyWrapUrl);

                        // Добавляем к EncryptedKey ссылку на зашифрованные 
                        // данные.
                        ek.AddReference(dRef);

                        KeyInfoX509Data data = new KeyInfoX509Data(EncryptCertificate);
                        ek.KeyInfo.AddClause(data);

                        // Добавляем ссылку на зашифрованный ключ к 
                        // зашифрованным данным.
                        edElement.KeyInfo.AddClause(new KeyInfoEncryptedKey(ek));

                    }

                    // Добавляем зашифрованные данные 
                    // к объекту EncryptedData.
                    edElement.CipherData.CipherValue = encryptedElement;
                }

                // Заменяем исходный узел на зашифрованный.
                EncryptedXml.ReplaceElement(elementToEncrypt, edElement, false);
                Log.Save("шифрование", "файл зашифрован", SignLog, filenameLog);
            }
            catch (Exception ex)
            {
                Log.Save("шифрование ошибка", ex.StackTrace + ex.Message, SignLog, filenameLog);
                return false;
            }
            return true;
        }

        /// <summary>
        /// дешифрование
        /// </summary>
        /// <returns></returns>
        private bool Decrypt()
        {
            try
            {
                Log.Save("шифрование", "файл дешифруется", SignLog, filenameLog);
                // Ищем все зашифрованные данные.
                XmlNamespaceManager nsmgr = new XmlNamespaceManager(doc.NameTable);
                nsmgr.AddNamespace("enc", "http://www.w3.org/2001/04/xmlenc#");
                XmlNodeList list = doc.SelectNodes("//enc:EncryptedData", nsmgr);

                // Создаем объект EncryptedXml.
                EncryptedXml exml = new EncryptedXml(doc);

                if (list != null)
                {
                    // Для всех зашифрованных данных.
                    foreach (XmlNode node in list)
                    {
                        XmlElement element = node as XmlElement;
                        EncryptedData encryptedData = new EncryptedData();
                        encryptedData.LoadXml(element);

                        // Находим подходящий ключ для расшифрования.
                        SymmetricAlgorithm decryptionKey = GetDecryptionKey(exml, encryptedData);
                        if (decryptionKey == null)
                        {
                            Console.WriteLine("Ключ для расшифрования сообщения не найден.");
                            return false;
                        }

                        // И на нем расшифровываем данные.
                        byte[] decryptedData = exml.DecryptData(encryptedData, decryptionKey);
                        exml.ReplaceData(element, decryptedData);
                    }
                }
                Log.Save("шифрование", "файл дешифрован", SignLog, filenameLog);
            }
            catch (Exception ex)
            {
                Log.Save("шифрование ошибка", ex.StackTrace + ex.Message, SignLog, filenameLog);
                return false;
            }
            return true;
        }

        /// <summary>
        /// дешифрование
        /// </summary>
        /// <returns></returns>
        private bool ClearSign()
        {
            try
            {
                Log.Save("Удаление подписи", "начало", SignLog, filenameLog);
                var s = doc.InnerXml;
                if (s.IndexOf("Signature") != -1)
                {
                    var s2 = s.Substring(0, s.IndexOf("Signature") - 1);
                    var s3 = s.Substring(s.IndexOf("/Signature>") + 11);
                    s = s2 + s3;
                    doc.InnerXml = s;
                }
                Log.Save("Удаление подписи", "конец", SignLog, filenameLog);
            }
            catch (Exception ex)
            {
                Log.Save("шифрование ошибка", ex.StackTrace + ex.Message, SignLog, filenameLog);
                return false;
            }
            return true;
        }
        
        /// <summary>
        /// дешифрование
        /// </summary>
        /// <returns></returns>
        private bool ClearSign(XmlDocument docX)
        {
            try
            {
                Log.Save("Удаление подписи", "начало", SignLog, filenameLog);
                doc = docX;
                var s = docX.InnerXml;
                if (s.IndexOf("Signature") != -1)
                {
                    var s2 = s.Substring(0, s.IndexOf("Signature") - 1);
                    var s3 = s.Substring(s.IndexOf("/Signature>") + 11);
                    s = s2 + s3;
                    docX.InnerXml = s;
                }
                Log.Save("Удаление подписи", "конец", SignLog, filenameLog);
            }
            catch (Exception ex)
            {
                Log.Save("шифрование ошибка", ex.StackTrace + ex.Message, SignLog, filenameLog);
                return false;
            }
            return true;
        }

        public bool AddNumber()
        {
            try
            {
                Log.Save("Добавление номера заявления", "начало", SignLog, filenameLog);
                var number = doc.FirstChild.NextSibling.FirstChild.InnerText.Split('_')[2];
                var elem = doc.FirstChild.NextSibling.FirstChild;

                while (elem.LocalName != "date")
                {
                    elem = elem.NextSibling;
                    if (elem.LocalName == "date")
                    {
                        if (elem.NextSibling.LocalName != "number")
                        {
                            XmlNode Number = doc.CreateElement(elem.Prefix, "number", elem.NamespaceURI);
                            Number.InnerText = number;                
                            doc.FirstChild.NextSibling.InsertAfter(Number, elem);
                            Log.Save("Добавление номера заявления", "конец", SignLog, filenameLog);
                        }
                    }
                }
            }
            catch (Exception ex)
            {               
                Log.Save("Добавление номера заявления", ex.StackTrace + ex.Message, SignLog, filenameLog);
                return false; 
            }

            return true;
        }

        public bool AddNumber(XmlDocument docX)
        {
            try
            {
                Log.Save("Добавление номера заявления", "начало", SignLog, filenameLog);
                var s = docX.InnerXml;
                if (s.IndexOf("Signature") != -1)
                {
                    var s2 = s.Substring(0, s.IndexOf("Signature") - 1);
                    var s3 = s.Substring(s.IndexOf("/Signature>") + 11);
                    s = s2 + s3;
                    docX.InnerXml = s;
                }
                Log.Save("Добавление номера заявления", "конец", SignLog, filenameLog);
            }
            catch (Exception ex)
            {
                Log.Save("Добавление номера заявления", ex.StackTrace + ex.Message, SignLog, filenameLog);
                return false;
            }

            return true;
        }

        /// <summary>
        /// получить ключ для расшифрования
        /// </summary>
        /// <param name="exml"></param>
        /// <param name="encryptedData"></param>
        /// <returns></returns>
        private SymmetricAlgorithm GetDecryptionKey(EncryptedXml exml, EncryptedData encryptedData)
        {
            IEnumerator encryptedKeyEnumerator = encryptedData.KeyInfo.GetEnumerator();
            // Проходим по всем KeyInfo
            while (encryptedKeyEnumerator.MoveNext())
            {
                // пропускам все что неизвестно.
                KeyInfoEncryptedKey current = encryptedKeyEnumerator.Current
                    as KeyInfoEncryptedKey;
                if (current == null)
                    continue;
                // до первого EncryptedKey
                EncryptedKey encryptedKey = current.EncryptedKey;
                if (encryptedKey == null)
                    continue;
                KeyInfo keyinfo = encryptedKey.KeyInfo;
                // Проходим по всем KeyInfo зашифрования ключа.
                IEnumerator srcKeyEnumerator = keyinfo.GetEnumerator();
                while (srcKeyEnumerator.MoveNext())
                {
                    // пропускам все что неизвестно.
                    KeyInfoX509Data keyInfoCert = srcKeyEnumerator.Current
                        as KeyInfoX509Data;
                    if (keyInfoCert == null)
                        continue;
                    AsymmetricAlgorithm alg = DecryptCertificate.PrivateKey;
                    if (alg == null)
                        continue;
                    // и ГОСТ алгоритмом секретного ключа.
                    Gost3410 gost = alg as Gost3410;
                    if (gost == null)
                        continue;
                    return CPEncryptedXml.DecryptKeyClass(encryptedKey.CipherData.CipherValue,
                        gost, encryptedData.EncryptionMethod.KeyAlgorithm);
                }
            }
            return null;
        }

    }
}
