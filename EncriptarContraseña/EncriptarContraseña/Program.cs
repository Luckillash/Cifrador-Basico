using System;
using System.Security.Cryptography;
using System.Text;

namespace EncryptDecryptPasswordCsharp
{
    class Program
    {
        static void Main(string[] args)
        {
            var text = "This is my password to protect";

            var encryptedText = EncryptPlainTextToCipherText(text);

            var decryptedText = DecryptCipherTextToPlainText(encryptedText);


            Console.WriteLine("Passed Text = " + text);

            Console.WriteLine("EncryptedText = " + encryptedText);

            Console.WriteLine("DecryptedText = " + decryptedText);

            Console.ReadLine();

        }

        //This security key should be very complex and Random for encrypting the text. This playing vital role in encrypting the text.
        private const string SecurityKey = "ComplexKeyHere_12121";

        //This method is used to convert the plain text to Encrypted/Un-Readable Text format.
        public static string EncryptPlainTextToCipherText(string PlainText)
        {

            // Getting the bytes of Input String.
            byte[] toEncryptedArray = UTF8Encoding.UTF8.GetBytes(PlainText);

            MD5CryptoServiceProvider objMD5CryptoService = new MD5CryptoServiceProvider();

            //Gettting the bytes from the Security Key and Passing it to compute the Corresponding Hash Value.
            byte[] securityKeyArray = objMD5CryptoService.ComputeHash(UTF8Encoding.UTF8.GetBytes(SecurityKey));

            //De-allocatinng the memory after doing the Job.
            objMD5CryptoService.Clear();

            var objTripleDESCryptoService = new TripleDESCryptoServiceProvider();

            //Assigning the Security key to the TripleDES Service Provider.
            objTripleDESCryptoService.Key = securityKeyArray;

            //Mode of the Crypto service is Electronic Code Book.
            objTripleDESCryptoService.Mode = CipherMode.ECB;

            //Padding Mode is PKCS7 if there is any extra byte is added.
            objTripleDESCryptoService.Padding = PaddingMode.PKCS7;


            var objCrytpoTransform = objTripleDESCryptoService.CreateEncryptor();

            //Transform the bytes array to resultArray
            byte[] resultArray = objCrytpoTransform.TransformFinalBlock(toEncryptedArray, 0, toEncryptedArray.Length);

            objTripleDESCryptoService.Clear();

            return Convert.ToBase64String(resultArray, 0, resultArray.Length);

        }

        //This method is used to convert the Encrypted/Un-Readable Text back to readable  format.
        public static string DecryptCipherTextToPlainText(string CipherText)
        {

            byte[] toEncryptArray = Convert.FromBase64String(CipherText);

            MD5CryptoServiceProvider objMD5CryptoService = new MD5CryptoServiceProvider();

            //Gettting the bytes from the Security Key and Passing it to compute the Corresponding Hash Value.
            byte[] securityKeyArray = objMD5CryptoService.ComputeHash(UTF8Encoding.UTF8.GetBytes(SecurityKey));

            objMD5CryptoService.Clear();

            var objTripleDESCryptoService = new TripleDESCryptoServiceProvider();

            //Assigning the Security key to the TripleDES Service Provider.
            objTripleDESCryptoService.Key = securityKeyArray;

            //Mode of the Crypto service is Electronic Code Book.
            objTripleDESCryptoService.Mode = CipherMode.ECB;

            //Padding Mode is PKCS7 if there is any extra byte is added.
            objTripleDESCryptoService.Padding = PaddingMode.PKCS7;

            var objCrytpoTransform = objTripleDESCryptoService.CreateDecryptor();

            //Transform the bytes array to resultArray
            byte[] resultArray = objCrytpoTransform.TransformFinalBlock(toEncryptArray, 0, toEncryptArray.Length);

            objTripleDESCryptoService.Clear();

            //Convert and return the decrypted data/byte into string format.
            return UTF8Encoding.UTF8.GetString(resultArray);

        }

        public static string CalculateMD5Hash(string input)
        {

            // To calculate MD5 hash from an input string
            MD5 md5 = MD5.Create();

            byte[] inputBytes = Encoding.ASCII.GetBytes(input);

            byte[] hash = md5.ComputeHash(inputBytes);

            // convert byte array to hex string
            StringBuilder sb = new StringBuilder();

            for (int i = 0; i < hash.Length; i++)
            {

                //to make hex string use lower case instead of uppercase add parameter "X2"
                sb.Append(hash[i].ToString("X2"));

            }

            return sb.ToString();

        }

    }

}