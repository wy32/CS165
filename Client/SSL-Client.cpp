#include <stdio.h>
#include <iostream>
#include <sstream>
#include <unistd.h>
#include <malloc.h>
#include <string>
#include <stdlib.h>
#include <fstream>
#include <sys/socket.h>
#include <resolv.h>
#include <vector>

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
    	method = SSLv23_client_method();  
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

	int iPortNum=-1;
	int iHost=-1;
	char *portnum;
	char *host;
	BIO *sbio;

 	SSL_CTX *ctx;
 	SSL *ssl;

	//check correct inputs
	if ( argc < 6)
    	{
        	printf("Usage: client -server <hostname> -port <portnum> <filename>\n");
        	exit(0);
    	}

	//check the -port flag index
	for(int i=0; i<argc; i++)
	{
		if(strcmp(argv[i], "-port") == 0)
			iPortNum=i;
		if(strcmp(argv[i], "-server") == 0)
			iHost=i;  
	}
	//Check we got the port flag
	if ( iPortNum == -1 )
    	{
        	printf("Usage: server -port <portnum>\n");
        	exit(0);
    	}
	iPortNum++;
	//Check we got the server flag
	if ( iHost == -1 )
    	{
        	printf("Usage: server -port <portnum>\n");
        	exit(0);
    	}
	iHost++;

	//Stores the hostname and port#
	portnum = argv[iPortNum];
	host = argv[iHost];

	//Establish an SSL connection with the server
	SSL_library_init();
 	ctx = InitServerCTX();
	SSL_CTX_set_verify(ctx,SSL_VERIFY_NONE,NULL);
 
	//Creates a new BIO chain consisting of an SSL BIO (using ctx) followed by a connect BIO
 	sbio = BIO_new_ssl_connect(ctx);
 	BIO_get_ssl(sbio, &ssl); //Binds sbio to ssl, so we can use all the SSL library functions
 	if(!ssl) {
   		cout<<"Can't locate SSL pointer";
 	}

	//Creates the name <hostname:portnumber>
	char* name = strcat(strcat(host,":"),portnum);
	
	//Creates a new connection
	sbio = BIO_new_connect(name);

 	//attempts to connect the supplied BIO. It returns 1 if the connection was established successfully.
 	if(BIO_do_connect(sbio) <= 0) {
        	cout<<"Error connecting to server";
	}

	//binds to the BIO addrss
 	if(BIO_do_handshake(sbio) <= 0) {
        	cout<<"Error establishing SSL connection";
 	}

	//Seed a cryptographically secure PRNG and use it to generate a random number (challenge).
	srand (time(NULL));
	int num = rand() % 1000 + 1;
	cout<<"Rand#: "<<num<<endl;
	
	//Converts to char* to use it later in the encryption	
	stringstream strs;
  	strs << num;
  	string temp_str = strs.str();
  	const char* msg = temp_str.c_str();
	
	//Loads the public key
	BIO *pubBpo = BIO_new_file("rsapublickey.pem", "r");
	RSA *pubKey = PEM_read_bio_RSA_PUBKEY(pubBpo, NULL, NULL, NULL);

	//Encrypt the challenge using the server’s RSA public key.
	unsigned char cipher[RSA_size(pubKey)];
    	RSA_public_encrypt(sizeof(msg),(unsigned char*)msg,(unsigned char*)cipher,pubKey, RSA_PKCS1_PADDING);

	//send the encrypted challenge to the server.
	BIO_write(sbio,cipher,sizeof(cipher));

	//Hash the un-encrypted challenge using SHA1.
	unsigned char* hashMsg = (unsigned char*)msg;
	unsigned char hash[RSA_size(pubKey)];
	
	//Hash the message
    	SHA1(hashMsg, sizeof(hashMsg), (unsigned char*)hash);  
	
	//Receive the signed hash of the random challenge from the server.
	unsigned char recCipher2[RSA_size(pubKey)]; 
	BIO_read(sbio,recCipher,sizeof(recCipher));

	//recover the hash using the RSA public key
	unsigned char recCipher[RSA_size(pubKey)];
	unsigned char msg2[RSA_size(pubKey)];
    	RSA_public_decrypt(sizeof(msg2),(unsigned char*)recCipher,(unsigned char*)msg2,pubKey, RSA_PKCS1_PADDING);

	//Compare the generated and recovered hashes above, to verify that the server received and decrypted the challenge properly.
	char* compHash1 = (char*)msg2;
	char* compHash2 = (char*)hash;

	//Get the filename
	char* infilename = argv[5];
	unsigned char msg3[RSA_size(pubKey)];
	

	ofstream myfile;
	myfile.open (infilename);

	//Compare the Hashes
	if (strncmp(compHash1,compHash2,20) == 0)
	{	
		//Encrypt the filename
		unsigned char cipher2[RSA_size(pubKey)];
    		RSA_public_encrypt(20,(unsigned char*)infilename,(unsigned char*)cipher2,pubKey, RSA_PKCS1_PADDING);

		//Send the filename request to the server
		BIO_write(sbio,cipher2,sizeof(cipher2));
		
		//Write the file
		while(BIO_read(sbio,recCipher2,sizeof(recCipher2))>0)	
		{	
			RSA_public_decrypt(sizeof(recCipher2),(unsigned char*)recCipher2,(unsigned char*)msg3,pubKey, RSA_PKCS1_PADDING);
			cout<<msg3;
			myfile<<msg3;
			
		}
		cout<<endl;
	}
	myfile.close();

 	BIO_free_all(sbio);
}
