// DNS Query Program on Linux
//Header Files
#include<stdio.h>	//printf
#include<string.h>	//strlen
#include<stdlib.h>	//malloc
#include<sys/socket.h>	//you know what this is for
#include<arpa/inet.h>	//inet_addr , inet_ntoa , ntohs etc
#include<netinet/in.h>
#include<unistd.h>	//getpid

//List of DNS Servers registered on the system
char dns_servers[10][100];
int dns_server_count = 0;
//Types of DNS resource records :)

#define T_A 1 //Ipv4 address
#define T_NS 2 //Nameserver
#define T_CNAME 5 // canonical name
#define T_SOA 6 /* start of authority zone */
#define T_PTR 12 /* domain name pointer */
#define T_MX 15 //Mail server

//Function Prototypes
void ngethostbyname (unsigned char*, char *, int);
void ChangetoDnsNameFormat (unsigned char*,unsigned char*);
unsigned char* ReadName (unsigned char*,unsigned char*,int*);
void get_dns_servers();

//DNS header structure
struct DNS_HEADER
{
	unsigned short id; // identification number

	unsigned char rd :1; // recursion desired
	unsigned char tc :1; // truncated message
	unsigned char aa :1; // authoritive answer
	unsigned char opcode :4; // purpose of message
	unsigned char qr :1; // query/response flag

	unsigned char rcode :4; // response code
	unsigned char cd :1; // checking disabled
	unsigned char ad :1; // authenticated data
	unsigned char z :1; // its z! reserved
	unsigned char ra :1; // recursion available

	unsigned short q_count; // number of question entries
	unsigned short ans_count; // number of answer entries
	unsigned short auth_count; // number of authority entries
	unsigned short add_count; // number of resource entries
};


//Constant sized fields of query structure
struct QUESTION {
	unsigned short qtype;
	unsigned short qclass;
};


//Constant sized fields of the resource record structure

#pragma pack(push, 1)
struct R_DATA
{
	unsigned short type;
	unsigned short _class;
	unsigned int ttl;
	unsigned short data_len;
};

#pragma pack(pop)

//Pointers to resource record contents
struct RES_RECORD {
	unsigned char *name;
	struct R_DATA *resource;
	unsigned char *rdata;
};

//Structure of a Query
typedef struct
{
	unsigned char *name;
	struct QUESTION *ques;
} QUERY;

// int main( int argc , char *argv[])
// {
// 	unsigned char hostname[100];

// 	//Get the DNS servers from the resolv.conf file
// 	get_dns_servers();
	
// 	//Get the hostname from the terminal
// 	printf("Enter Hostname to Lookup : ");
// 	scanf("%s", hostname);
	
// 	//Now get the ip of this hostname , A record
// 	ngethostbyname(hostname , T_A);

// 	return 0;
// }

void printResponseOverview(struct DNS_HEADER* dns) {
	printf("======   crDig   ======\n");
	printf("====     header    ====\n");
	printf("QUERY: %d, ANSWER: %d, AUTHORITY: %d, ADDITIONAL: %d\n", ntohs(dns->q_count), ntohs(dns->ans_count), ntohs(dns->auth_count), ntohs(dns->add_count));
}

/*
 * Perform a DNS query by sending a packet
 * */
void ngethostbyname(unsigned char *host, char * server, int query_type) {

	// init dns servers
	get_dns_servers();

	printf("search information: %s\n", host);

	// select the first one
	// printf("dns server: %s\n", dns_servers[0]);

	unsigned char buf[65536],*qname,*reader;
	int i , j , stop , s;

	struct sockaddr_in a;
	struct RES_RECORD answers[20],auth[20],addit[20]; //the replies from the DNS server
	struct sockaddr_in dest;

	struct DNS_HEADER *dns = NULL;
	struct QUESTION *qinfo = NULL;

	s = socket(AF_INET , SOCK_DGRAM , IPPROTO_UDP); //UDP packet for DNS queries

	// if deleting the two lines below, there will be Permission Denied Error
	int on=1;
  	setsockopt(s,SOL_SOCKET,SO_REUSEADDR | SO_BROADCAST,&on,sizeof(on));

	dest.sin_family = AF_INET;
	int port = 53;
	dest.sin_port = htons(port);

	// select server
	if(strlen(server) == 0) {
		dest.sin_addr.s_addr = inet_addr(dns_servers[0]);
	}else 
		dest.sin_addr.s_addr = inet_addr(server); //dns servers

	// show used server
	printf("dns server: %s\n", inet_ntoa(dest.sin_addr));

	//Set the DNS structure to standard queries
	dns = (struct DNS_HEADER *)&buf;

	dns->id = (unsigned short) htons(getpid());
	dns->qr = 0; //This is a query
	dns->opcode = 0; //This is a standard query
	dns->aa = 0; //Not Authoritative
	dns->tc = 0; //This message is not truncated (shortened)
	dns->rd = 1; //Recursion Desired
	dns->ra = 0; //Recursion not available! hey we dont have it (lol)
	dns->z = 0;
	dns->ad = 0;
	dns->cd = 0;
	dns->rcode = 0;
	dns->q_count = htons(1); //we have only 1 question
	dns->ans_count = 0;
	dns->auth_count = 0;
	dns->add_count = 0;

	//point to the query portion
	qname =(unsigned char*)&buf[sizeof(struct DNS_HEADER)];

	// change format...
	ChangetoDnsNameFormat(qname, host);

	// set a standard query struct just after the dns header
	qinfo =(struct QUESTION*)&buf[sizeof(struct DNS_HEADER) + (strlen((const char*)qname) + 1)]; //fill it

	qinfo->qtype = htons(query_type); // select default query type: 01 => Type A
	qinfo->qclass = htons(1); // class IN

	if( sendto(s,(char*)buf,sizeof(struct DNS_HEADER) + (strlen((const char*)qname)+1) + sizeof(struct QUESTION),0,(struct sockaddr*)&dest,sizeof(dest)) < 0) {
		perror("sendto failed");
		return;
	}
	
	//Receive the answer
	i = sizeof dest;
	if(recvfrom (s,(char*)buf, 65536, 0, (struct sockaddr*)&dest , (socklen_t*)&i ) < 0) {
		perror("recvfrom failed");
		return;
	}

	dns = (struct DNS_HEADER*) buf;

	// print overview result
	printResponseOverview(dns);

	//move ahead of the dns header and the query field
	reader = &buf[sizeof(struct DNS_HEADER) + (strlen((const char*)qname)+1) + sizeof(struct QUESTION)];

	//Start reading answers
	stop=0;

	for(i = 0;i < ntohs(dns->ans_count); i++) {
		answers[i].name=ReadName(reader,buf,&stop);
		reader = reader + stop;

		answers[i].resource = (struct R_DATA*)(reader);
		reader = reader + sizeof(struct R_DATA);

		if(ntohs(answers[i].resource->type) == 1) //if its an ipv4 address
		{
			answers[i].rdata = (unsigned char*)malloc(ntohs(answers[i].resource->data_len));

			for(j=0 ; j<ntohs(answers[i].resource->data_len) ; j++) {
				answers[i].rdata[j]=reader[j];
			}

			answers[i].rdata[ntohs(answers[i].resource->data_len)] = '\0';

			reader = reader + ntohs(answers[i].resource->data_len);
		}
		else {
			answers[i].rdata = ReadName(reader,buf,&stop);
			reader = reader + stop;
		}
	}

	// for(int i = 0; i < ntohs(dns->auth_count); i++) {
	// 	auth[i].name = ReadName(reader,buf,&stop);
	// 	reader += stop;

	// 	auth[i].resource = (struct R_DATA *)(reader);
	// 	reader += sizeof(struct R_DATA);

	// 	auth[i].rdata = ReadName(reader,buf,&stop);
	// 	reader += stop;
	// }

	// for(int i = 0; i < ntohs(dns->add_count); i++) {
	// 	addit[i].name = ReadName(reader,buf,&stop);
	// 	reader += stop;

	// 	addit[i].resource = (struct R_DATA *)(reader);
	// 	reader += sizeof(struct R_DATA);

	// 	if(ntohs(addit[i].resource->type) == 1) //if its an ipv4 address
	// 	{
	// 		addit[i].rdata = (unsigned char*)malloc(ntohs(addit[i].resource->data_len));

	// 		for(j=0 ; j<ntohs(addit[i].resource->data_len) ; j++) {
	// 			answers[i].rdata[j]=reader[j];
	// 		}

	// 		addit[i].rdata[ntohs(addit[i].resource->data_len)] = '\0';

	// 		reader = reader + ntohs(addit[i].resource->data_len);
	// 	}
	// 	else {
	// 		addit[i].rdata = ReadName(reader,buf,&stop);
	// 		printf("stop: %d\n", stop);
	// 		reader = reader + stop;
	// 	}
	// }

	//print answers
	printf("\nANSWER SECTION: %d \n" , ntohs(dns->ans_count) );
	printf("Name\t\t\t\tType\t\tTTL\t\tHost\n");
	for(i=0 ; i < ntohs(dns->ans_count) ; i++)
	{
		printf("%-32s",answers[i].name);
		switch(ntohs(answers[i].resource->type)) {
			case T_A:
				printf("A\t\t");
				long *p;
				
				printf("%u\t\t", ntohl(answers[i].resource->ttl));
				p=(long*)answers[i].rdata;
				a.sin_addr.s_addr=(*p); //working without ntohl
				printf("%s",inet_ntoa(a.sin_addr));				
				break;
			case T_NS:
				printf("NS\t\t");
				// long *p;
				printf("%u\t\t", ntohl(answers[i].resource->ttl));
				p = (long*)answers[i].rdata;
				a.sin_addr.s_addr = (*p);
				printf("%s", inet_ntoa(a.sin_addr));
				break;
			case T_CNAME:
				printf("CNAME\t\t");
				printf("%u\t\t", ntohl(answers[i].resource->ttl));
				printf("%s",answers[i].rdata);
				break;
			case T_MX:
				printf("MX\n");
				break;
			
		}
		printf("\n");
	}

	// printf("Auth:\n");

	// for(int i = 0; i < ntohs(dns->auth_count); i++) {
	// 	printf("Name: %s ", auth[i].name);
	// 	printf("has name server: %s", auth[i].resource);
	// }

	// printf("additional: \n");

	// for(int i = 0; i < ntohs(dns->add_count); i++) {
	// 	printf("%s\t\t",addit[i].name);
	// 	switch(ntohs(addit[i].resource->type)) {
	// 		case T_A:
	// 			printf("A\t\t");
				
	// 			long *p;
	// 			p=(long*)addit[i].rdata;
	// 			a.sin_addr.s_addr=(*p); //working without ntohl
	// 			printf("%s",inet_ntoa(a.sin_addr));				
	// 			break;
	// 		case T_NS:
	// 			printf("NS\t\t");
				// long *p;
	// 			p = (long*)addit[i].rdata;
	// 			a.sin_addr.s_addr = (*p);
	// 			printf("%s", inet_ntoa(a.sin_addr));
	// 			break;
	// 		case T_CNAME:
	// 			printf("CNAME\t");
	// 			// p = (long*)answers[i].rdata;
	// 			// a.sin_addr.s_addr = (*p);
	// 			// printf("%s", inet_ntoa(a.sin_addr));
	// 			printf("%s",addit[i].rdata);
	// 			break;
	// 		case T_MX:
	// 			break;
			
	// 	}
	// }

	printf("SERVER: %s#%d\n", inet_ntoa(dest.sin_addr), port);


	return;
}

// like www.baidu.com
// 1. .
// 2. .com
// 3. baidu.com
// 4. www.baidu.com

int traceTime(unsigned char * host) {
	int trace_time = 0;
	for(int i = 0; i < strlen(host); i++)
		if(host[i] == '.') 
			trace_time++;
	return trace_time+2;
}

void getTracePath(unsigned char trace_path[50][100], int trace_time, unsigned char * host) {
	int ptr = 0;
	unsigned char * _host = host;
	for(int i = trace_time - 1; i >= 0; i--) {
		if(i == 0) {
			strcpy(trace_path[i], ".");
		}else {
			strcpy(trace_path[i], (unsigned char *)_host);
		}
		while((unsigned char)*_host != '.') {
			_host++;
		}
		_host++;
	}
}

void ngethostbyname_trace(unsigned char *host, char * server, int query_type) {


	int trace_time = traceTime(host);
	unsigned char trace_path[50][100] = {0};
	getTracePath(trace_path, trace_time, host);

	for(int _i = 0; _i < trace_time; _i++) {
	// init dns servers
	get_dns_servers();

	// printf("search information: %s\n", trace_path[i]);

	unsigned char buf[65536],*qname,*reader;
	int i , j , stop , s;

	struct sockaddr_in a;
	struct RES_RECORD answers[20]; //the replies from the DNS server
	struct sockaddr_in dest;

	struct DNS_HEADER *dns = NULL;
	struct QUESTION *qinfo = NULL;

	s = socket(AF_INET , SOCK_DGRAM , IPPROTO_UDP); //UDP packet for DNS queries

	// if deleting the two lines below, there will be Permission Denied Error
	// just got the answer in Baidu
	int on=1;
  	setsockopt(s,SOL_SOCKET,SO_REUSEADDR | SO_BROADCAST,&on,sizeof(on));

	dest.sin_family = AF_INET;
	int port = 53;
	dest.sin_port = htons(port);

	// if having selected server
	if(strlen(server) == 0) {
		dest.sin_addr.s_addr = inet_addr(dns_servers[0]);
	}else 
		dest.sin_addr.s_addr = inet_addr(server); //dns servers
	
	// show used server
	printf("dns server: %s\n", inet_ntoa(dest.sin_addr));

	//Set the DNS structure to standard queries
	dns = (struct DNS_HEADER *)&buf;

	dns->id = (unsigned short) htons(getpid());
	dns->qr = 0; //This is a query
	dns->opcode = 0; //This is a standard query
	dns->aa = 0; //Not Authoritative
	dns->tc = 0; //This message is not truncated (shortened)
	dns->rd = 1; //Recursion Desired
	dns->ra = 0; //Recursion not available! hey we dont have it (lol)
	dns->z = 0;
	dns->ad = 0;
	dns->cd = 0;
	dns->rcode = 0;
	dns->q_count = htons(1); //we have only 1 question
	dns->ans_count = 0;
	dns->auth_count = 0;
	dns->add_count = 0;

	//point to the query portion
	qname =(unsigned char*)&buf[sizeof(struct DNS_HEADER)];

	// change format...
	ChangetoDnsNameFormat(qname, trace_path[_i]);

	// set a standard query struct just after the dns header
	qinfo =(struct QUESTION*)&buf[sizeof(struct DNS_HEADER) + (strlen((const char*)qname) + 1)]; //fill it
	if(_i != trace_time - 1) {
		qinfo->qtype = htons(T_NS); // type NS request
	}else 
		qinfo->qtype = htons(T_A);
	qinfo->qclass = htons(1); // class IN

	if( sendto(s,(char*)buf,sizeof(struct DNS_HEADER) + (strlen((const char*)qname)+1) + sizeof(struct QUESTION),0,(struct sockaddr*)&dest,sizeof(dest)) < 0) {
		perror("sendto failed");
		return;
	}
	
	//Receive the answer
	i = sizeof dest;
	if(recvfrom (s,(char*)buf, 65536, 0, (struct sockaddr*)&dest , (socklen_t*)&i ) < 0) {
		perror("recvfrom failed");
		return;
	}

	dns = (struct DNS_HEADER*) buf;

	// print overview result
	// this is not needed in trace section
	// printResponseOverview(dns);

	//move ahead of the dns header and the query field
	reader = &buf[sizeof(struct DNS_HEADER) + (strlen((const char*)qname)+1) + sizeof(struct QUESTION)];

	//Start reading answers
	stop=0;

	for(i = 0;i < ntohs(dns->ans_count); i++) {
		answers[i].name=ReadName(reader,buf,&stop);
		reader = reader + stop;

		answers[i].resource = (struct R_DATA*)(reader);
		reader = reader + sizeof(struct R_DATA);

		if(ntohs(answers[i].resource->type) == 1) //if its an ipv4 address
		{
			answers[i].rdata = (unsigned char*)malloc(ntohs(answers[i].resource->data_len));

			for(j=0 ; j<ntohs(answers[i].resource->data_len) ; j++) {
				answers[i].rdata[j]=reader[j];
			}

			answers[i].rdata[ntohs(answers[i].resource->data_len)] = '\0';

			reader = reader + ntohs(answers[i].resource->data_len);
		}
		else {
			answers[i].rdata = ReadName(reader,buf,&stop);
			reader = reader + stop;
		}
	}

	//print answers, we don't need in trace section
	// printf("\nANSWER SECTION: %d \n" , ntohs(dns->ans_count) );
	printf("Name\t\t\t\tType\t\tTTL\t\tHost\n");
	for(i=0 ; i < ntohs(dns->ans_count) ; i++)
	{
		// printf("%-20s\t\t",answers[i].name); something wrong with this
		printf("%-20s\t\t", trace_path[_i]);
		switch(ntohs(answers[i].resource->type)) {
			case T_A:
				// type
				printf("A\t\t");
				long *p;
				// TTL
				printf("%u\t\t", ntohl(answers[i].resource->ttl));
				p=(long*)answers[i].rdata;
				a.sin_addr.s_addr=(*p); //working without ntohl
				printf("%s",inet_ntoa(a.sin_addr));				
				break;
			case T_NS:
				printf("NS\t\t");
				// long *p;
				printf("%u\t\t", ntohl(answers[i].resource->ttl));

				p = (long*)answers[i].rdata;
				a.sin_addr.s_addr = (*p);
				printf("%s", answers[i].rdata);
				break;
			case T_CNAME:
				printf("CNAME\t\t");
				printf("%u\t\t", ntohl(answers[i].resource->ttl));
				printf("%s",answers[i].rdata);
				break;
			case T_MX:
				break;
			
		}
		printf("\n");
	}

	printf("SERVER: %s#%d\n", inet_ntoa(dest.sin_addr), port);
	}
	// ngethostbyname(host, server, 1);
	return;
}

/*
 * 
 * */
u_char* ReadName(unsigned char* reader,unsigned char* buffer,int* count) {
	unsigned char *name;
	unsigned int p=0,jumped=0,offset;
	int i , j;

	*count = 1;
	name = (unsigned char*)malloc(256);

	name[0]='\0';

	//read the names in 3www6google3com format
	while(*reader!=0)
	{
		if(*reader>=192) {
			offset = (*reader)*256 + *(reader+1) - 49152; //49152 = 11000000 00000000 ;)
			reader = buffer + offset - 1;
			jumped = 1; //we have jumped to another location so counting wont go up!
		}
		else {
			name[p++]=*reader;
		}

		reader = reader+1;

		if(jumped==0)
		{
			*count = *count + 1; //if we havent jumped to another location then we can count up
		}
	}

	name[p]='\0'; //string complete
	if(jumped==1)
	{
		*count = *count + 1; //number of steps we actually moved forward in the packet
	}

	//now convert 3www6google3com0 to www.google.com
	for(i=0;i<(int)strlen((const char*)name);i++) 
	{
		p=name[i];
		for(j=0;j<(int)p;j++) 
		{
			name[i]=name[i+1];
			i=i+1;
		}
		name[i]='.';
	}
	name[i-1]='\0'; //remove the last dot
	return name;
}

/*
 * Get the DNS servers from /etc/resolv.conf file on Linux
 * */
void get_dns_servers() {
	// strcpy(dns_servers[0], "202.144.0.131");
	strcpy(dns_servers[0], "202.114.0.131");
	strcpy(dns_servers[1], "202.114.0.242");
}

/*
 * This will convert www.google.com to 3www6google3com 
 * got it :)
 * */
void ChangetoDnsNameFormat(unsigned char* dns,unsigned char* host) {
	if(*host == '.' && *(host + 1) == '\0') {
		*dns = '\0';
		return;
	}
	int lock = 0 , i;
	strcat((char*)host,".");
	
	for(i = 0 ; i < strlen((char*)host) ; i++) {
		if(host[i]=='.') {
			*dns++ = i-lock;
			for(;lock<i;lock++) {
				*dns++=host[lock];
			}
			lock++; // or lock=i+1;
		}
	}

	*dns++='\0';

}
