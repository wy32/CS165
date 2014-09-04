#include <stdio.h>
#include <iostream>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <sys/socket.h>
#include <resolv.h>

#include "openssl/bio.h"
#include "openssl/ssl.h"
#include "openssl/err.h"
#include <openssl/rand.h>
#include <openssl/sha.h>

using namespace std;

SSL_CTX* InitServerCTX(void)
{   
	SSL_METHOD *method;
    	SSL_CTX *ctx;

    	OpenSSL_add_all_algorithms();  
    	SSL_load_error_strings();   
    	method = SSLv23_server_method();  
    	ctx = SSL_CTX_new(method);   
    
	if ( ctx == NULL )
    	{
        	ERR_print_errors_fp(stderr);
        	abort();
    	}
    	return ctx;
}

int main(int argc, char *argv[])
{   
	BIO *sbio,*addrss, *binfile, *hashedFile, *boutfile;
	int iPortNum=-1;
	char *portnum;
 	int len;
 	SSL_CTX *ctx;
 	SSL *ssl;

	//check correct inputs
	if ( argc < 2 )
    	{
        	printf("Usage: server -port <portnum>\n");
        	exit(0);
    	}

	//check the -port flag index
	for(int i=0; i<argc; i++)
	{
		if(strcmp(argv[i], "-port") == 0)
			iPortNum=i; 
	}
	//Check we got the port flag
	if ( iPortNum == -1 )
    	{
        	printf("Usage: server -port <portnum>\n");
        	exit(0);
    	}
	iPortNum++;

	//Initialize SSL
    	SSL_library_init();

	//Assigns the portnumber
    	portnum = argv[iPortNum];

	//Initialize server which returns the SSL_CTX
	ctx = InitServerCTX();
	SSL_CTX_set_verify(ctx,SSL_VERIFY_NONE,NULL); //sets to not check for certificates

	//Bind the ctx and the ssl socket
	sbio=BIO_new_ssl(ctx,0);
 	BIO_get_ssl(sbio, &ssl);
	
	//check for pointer error 
	if(!ssl) {
   		fprintf(stderr, "Can't locate SSL pointer\n");
 	}
	
	//Assign the port to the BIO
 	addrss=BIO_new_accept(portnum);

	//Attempts to create the accept socket and binds the BIO addrss to it
 	if(BIO_do_accept(addrss) <= 0) {
        	fprintf(stderr, "Error setting up accept BIO\n");
        	ERR_print_errors_fp(stderr);
        	return 0;
 	}

	//Await an incoming connection 
 	if(BIO_do_accept(addrss) <= 0) {
        	fprintf(stderr, "Error in connection\n");
        	ERR_print_errors_fp(stderr);
        	return 0;
 	}
	
	//complete an SSL handshake on the BIO and establish the SSL connection
 	if(BIO_do_handshake(addrss) <= 0) {
        	cout<<"Error in SSL handshake"<<endl;
        	return 0;
 	}
	
	//Load the Public and Private Keys
	BIO *priBpo = BIO_new_file("rsaprivatekey.pem", "r");
	RSA *priKey = PEM_read_bio_RSAPrivateKey(priBpo, NULL, NULL, NULL);

	BIO *pubBpo = BIO_new_file("rsapublickey.pem", "r");
	RSA *pubKey = PEM_read_bio_RSA_PUBKEY(pubBpo, NULL, NULL, NULL);

	
	//Receive an encrypted challenge from the client and decrypt it using the RSA private key.
	unsigned char tmpbuf[RSA_size(pubKey)];
	unsigned char msg[RSA_size(priKey)];
	BIO_read(addrss,tmpbuf,sizeof(tmpbuf)); //Reads the encrypted challenge

	//Decrypt the challenge using the RSA private key.
    	RSA_private_decrypt(sizeof(tmpbuf),(unsigned char*)tmpbuf,(unsigned char*)msg,priKey, RSA_PKCS1_PADDING);

	//Hash the challenge using SHA1
	unsigned char* hashMsg = (unsigned char*)msg; //Need to have same variable type as Client
	unsigned char hash[20];
    	SHA1(hashMsg, sizeof(hashMsg), (unsigned char*)hash); //Hashes the challenge   
	
	//Sign the hash
	unsigned char cipher[RSA_size(pubKey)];
	RSA_private_encrypt(sizeof(hash),(unsigned char*)hash, (unsigned char*)cipher,priKey,RSA_PKCS1_PADDING);

	//Send the signed hash to the client.
	BIO_write(addrss,cipher,sizeof(cipher));

	//Receive a filename request from the client.
	unsigned char tmpbuf2[RSA_size(pubKey)];

	//Receive an encrypted challenge from the client and decrypt it using the RSA private key.
	BIO_read(addrss,tmpbuf2,sizeof(tmpbuf));
	unsigned char msg2[RSA_size(priKey)];

	//Receive an encrypted challenge from the client and decrypt it using the RSA private key.
    	RSA_private_decrypt(sizeof(tmpbuf2),tmpbuf2,msg2,priKey, RSA_PKCS1_PADDING);
	
	//Cast the received file so we can open it
	char* newmessage2 = (char*)msg2;

	vector<char> content;
	char c;

	//Open the Requested File
	ifstream myfile;
  	myfile.open (newmessage2);
	if (myfile.is_open()) { cout<<"opened"; }
	else
		cout<<"file not opened";
	
	while (myfile.good())
     	{
          	c = myfile.get();
		content.push_back(c);
     	}

	//Send and encrypt the file
	for(int i=0; i<content.size()-2;)
	{	
		char contBuff[101];
		for(int k=0; k<100; k++)contBuff[k]=0;
		for(int j=0; j<100 && i<content.size()-2; j++)
		{
			contBuff[j] = content[i++];
			cout<<contBuff[j];
		}

		unsigned char cipher3[RSA_size(priKey)];
		RSA_private_encrypt(sizeof(contBuff),(unsigned char*)contBuff, (unsigned char*)cipher3,priKey,RSA_PKCS1_PADDING);
		BIO_write(addrss,cipher3,sizeof(cipher3));
	}

	myfile.close();

 	BIO_flush(addrss);
 	BIO_free_all(addrss);
}
