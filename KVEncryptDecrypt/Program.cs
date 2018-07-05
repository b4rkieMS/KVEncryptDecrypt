using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Clients.ActiveDirectory;
using System.Configuration;
using Microsoft.WindowsAzure.Storage.Auth;
using Microsoft.WindowsAzure.Storage;
using Microsoft.WindowsAzure.Storage.Blob;
using Microsoft.Azure.KeyVault;
using System.Threading;
using System.IO;

namespace KVEncryptDecrypt
{
    class Program
    {
        static void Main(string[] args)
        {
            /* OVERVIEW OF HOW THIS WORKS :
            The Azure Storage client SDK generates a content encryption key(CEK), which is a 
            one - time - use symmetric key. Customer data is encrypted using this CEK.
The CEK is then wrapped (encrypted) using the key encryption key(KEK). 
The KEK is identified by a key identifier and can be managed locally or stored in Azure Key 
Vault.
The Storage client itself never has access to the KEK. It just invokes the key wrapping 
algorithm that is provided by Key Vault. 
The encrypted data is then uploaded to the Azure Storage service.

Decryption is really when using the Resolver classes make sense.
The ID of the key used for encryption is associated with the blob in its metadata, so there 
is no reason for you to retrieve the key and remember the
association between key and blob.You just have to make sure that the key remains in Key Vault.
The private key of an RSA Key remains in Key Vault, so for decryption to occur, the Encrypted 
Key from the blob metadata that contains the CEK is sent to
Key Vault for decryption.*/

            Console.WriteLine("Azure Key Vault Demo : Encryption and decryption of a file.");
            Console.WriteLine("Please enter storage account NAME :");
            var accountN = Console.ReadLine();
            Console.WriteLine("Please enter storage account KEY :");
            var accountK = Console.ReadLine();

            // This is standard code to interact with Blob storage.
            StorageCredentials creds = new StorageCredentials(
                   accountN,accountK);
            CloudStorageAccount account = new CloudStorageAccount(creds, useHttps: true);
            CloudBlobClient client = account.CreateCloudBlobClient();
            CloudBlobContainer contain = client.GetContainerReference(ConfigurationManager.AppSettings["container"]);
            contain.CreateIfNotExists();

            // The Resolver object is used to interact with Key Vault for Azure Storage.
            // This is where the GetToken method from above is used.
            KeyVaultKeyResolver cloudResolver = new KeyVaultKeyResolver(GetToken);


            // Retrieve the key that you created previously.
            // The IKey that is returned here is an RsaKey.
            // 
            Console.WriteLine("Please enter URL of key, for example : https://myKeyVault.vault.azure.net/keys/MyKeyDemo");
            var kv = Console.ReadLine();
            var rsa = cloudResolver.ResolveKeyAsync(kv, CancellationToken.None).GetAwaiter().GetResult();

            // Now you simply use the RSA key to encrypt by setting it in the BlobEncryptionPolicy.
            BlobEncryptionPolicy policy = new BlobEncryptionPolicy(rsa, null);
            BlobRequestOptions options = new BlobRequestOptions() { EncryptionPolicy = policy };

            // Reference a block blob.
            CloudBlockBlob blob = contain.GetBlockBlobReference("MyFile.txt");

            // Upload using the UploadFromStream method.
            Console.WriteLine("Ensure MyFile.txt is placed in the temp directory.");
            Console.WriteLine("Press any key to continue...");
            Console.ReadLine();

            using (var stream = System.IO.File.OpenRead(@"C:\temp\MyFile.txt"))
                blob.UploadFromStream(stream, stream.Length, null, options, null);

            Console.WriteLine("File encrypted and uploaded....");
            Console.WriteLine("Now use Storage Explorer or portal to retrive the encrypted file from the storage account and view it.");
            Console. WriteLine("Press ANY Key to continue...");
            Console.ReadLine();

            Console.WriteLine("Now let's retrieve and decrypt...");
            // In this case, we will not pass a key and only pass the resolver because
            // this policy will only be used for downloading / decrypting.
            BlobEncryptionPolicy policydecrypt = new BlobEncryptionPolicy(null, cloudResolver);
            BlobRequestOptions optionsdecrypt = new BlobRequestOptions() { EncryptionPolicy = policydecrypt };

            
            using (var np = File.Open(@"C:\temp\MyFileDecrypted.txt", FileMode.Create))
                blob.DownloadToStream(np, null, options, null);

            Console.WriteLine("File Downloaded and decrypted as MyFileDecrypted.txt into the temp directory. Check it out!");
            Console.WriteLine("Press ANY Key to continue...");
            Console.ReadLine();
        }




        private async static Task<string> GetToken(string authority, string resource, string scope)
        {
            Console.WriteLine("Please enter ClientID");
            var cId = Console.ReadLine();
            Console.WriteLine("Please enter Client Secret");
            var cSecret = Console.ReadLine();

            var authContext = new AuthenticationContext(authority);
            ClientCredential clientCred = new ClientCredential(
                 cId,cSecret);
            AuthenticationResult result = await authContext.AcquireTokenAsync(resource, clientCred);

            if (result == null)
                throw new InvalidOperationException("Failed to obtain the JWT token");

            return result.AccessToken;
        }
    }
}
