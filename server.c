#include "unpifiplus.h"
#include <stdbool.h>
#include "./unprtt.h"
#include <setjmp.h>

#define INTERVAL 500
#define PAYLOAD 512

#define RTT_RTOCALC(ptr) ((ptr)->rtt_srtt + ((ptr)->rtt_rttvar << 2))

extern struct ifi_info *get_ifi_info_plus(int family, int doaliases);
extern void free_ifi_info_plus(struct ifi_info *ifihead);
void str_client(int,char*,char*, uint16_t, char [], int,int);
static void sig_alrm(int);
void send_datagram(int, char[], int,int);
void sendagain(int seq, int sockfd, char *buffer);
int recvagain(int sockfd);

// Structure to read from server.in file
typedef struct input_text
{
	int port;
	int w_size;
}input_file;

struct struct_sock // structure to store the information for each server socket
{
	int sockfd;
	char *ipaddr;
	char *ipmask;
	char *ipsubnet;
};


struct hdr {
    uint32_t seq;
    uint32_t ack;
    int adv_window;
    uint32_t ts;
}sendhdr = {}, recvhdr = {};

typedef struct datagram {
    struct hdr header;
    char buffer[PAYLOAD - sizeof(struct hdr)];
} datagram;


typedef struct clientkeeper {
    pid_t pid;
    char *ip_addr;
    uint16_t port_num;
    struct clientkeeper *next;
} ckeeper;

ckeeper *lptr = NULL;

void sig_chld(int sig_num) {
    pid_t pid;
    int stat;
    while ( (pid = waitpid(-1, &stat, WNOHANG)) > 0) {
        ckeeper *nodea;
        if(lptr->pid == pid) {
            nodea = lptr->next;
            free(lptr);
            lptr = nodea;
        }
        else {
            ckeeper *tptr = lptr;
            while( tptr->next ) {
                if (tptr->next->pid == pid) {
                    nodea = tptr->next->next;
                    free(tptr->next);
                    tptr->next = nodea;
                }
                if(tptr->next)
                    tptr = tptr->next;
            }
        }
    }
    return;
}


static int rtt_minimax( int rto) {
    if (rto < RTT_RXTMIN)
        rto = RTT_RXTMIN;
    else if (rto > RTT_RXTMAX)
        rto = RTT_RXTMAX;
    return rto;
}

void rtt_init(struct rtt_info *ptr) {
    struct timeval tv;
    Gettimeofday(&tv, NULL);
    ptr->rtt_base = tv.tv_sec;
    ptr->rtt_rtt = 0;
    ptr->rtt_srtt = 0;
    ptr->rtt_rttvar = 150;
    ptr->rtt_rto = rtt_minimax(RTT_RTOCALC(ptr));
}

uint32_t rtt_ts(struct rtt_info *ptr) {
    uint32_t ts;
    struct timeval tv;
    Gettimeofday(&tv, NULL);
    ts = ((tv.tv_sec - ptr->rtt_base) * 1000) + (tv.tv_usec / 1000);
    return ts;
}

void rtt_newpack(struct rtt_info *ptr) {
    ptr->rtt_nrexmt = 0;
}

int rtt_start(struct rtt_info *ptr) {
    return ((int) (ptr->rtt_rto));
}

void rtt_stop(struct rtt_info *ptr, uint32_t ms) {
    int delta;
    ptr->rtt_rtt = ms;

    delta = ptr->rtt_rtt - ptr->rtt_srtt;
    ptr->rtt_srtt += ( delta >> 3);
    if(delta < 0)
        delta = -delta;
    ptr->rtt_rttvar += ((delta - ptr->rtt_rttvar) >> 2);
    ptr->rtt_rto = rtt_minimax(RTT_RTOCALC(ptr));
}

int rtt_timeout(struct rtt_info *ptr) {
    ptr->rtt_rto = rtt_minimax(ptr->rtt_rto << 1);
    if (++ptr->rtt_nrexmt > RTT_MAXNREXMT)
        return -1;
    return 0;
}

void read_from_file(input_file *ip)
{
	FILE *fp;
	char rbuff[2][MAXLINE];
	int index=0;

	// open the server.in file to read its contents
	fp=fopen("server.in","r");
	while((fgets(rbuff[index],MAXLINE,fp)!=NULL) && (index<2))
	{
		index++;
	}

	ip->port= (uint16_t) atoi(rbuff[0]);
	ip->w_size=atoi(rbuff[1]);
}

int main(int argc,char *argv[])
{

	struct struct_sock sock_info[20];
	struct sockaddr_in *ptr, *sa, cliaddr, pservaddr, pcliaddr;
	struct ifi_info *ifi;

	socklen_t clilen;
	char *ipserv,*ipclient;
	const int on=1;
    char *addr,*ip,*netmask, *tempaddr,*tempmask,*ptr1,*ptr2,*ptr3,*ptr4,*tempcli;
    char *subnet,*clitok,*servmask,*tservaddr,*servtok,*servaddr;
	char recvline[MAXLINE],filename[MAXLINE],localhost[MAXLINE]="127.0.0.1";
	const char token[2]=".";
	int i=0,k,len,structlen,j=0,l=0,arrlen,n,m, q;
	int fdp1,listenfd,connfd,maxfdp=0;
	fd_set rset;
	pid_t pid, parpid;
	uint16_t cli_port;
	int cliadwin=0;// client advertising window
	int finc=0; // counter used to get filename
    ckeeper *tptr;

	input_file infile;
    signal(SIGCHLD, sig_chld);
	read_from_file(&infile);

	if((ifi=get_ifi_info_plus(AF_INET,1))==NULL) // to get all the IP addresses of the server
		err_sys("get_ifi_info error");


    printf ("Server Interface details:\n");
	for(;ifi!=NULL;ifi=ifi->ifi_next) // looping through the ifi_info structure
	{
        char tempmask[16], tempaddr[16];
		if((sock_info[i].sockfd=socket(AF_INET,SOCK_DGRAM,0))<0) // creating a socket for each IP address of the server
			err_sys("UDP create socket error");

		if(setsockopt(sock_info[i].sockfd,SOL_SOCKET,SO_REUSEADDR,&on,sizeof(on))<0)
			err_sys("setsocket option:SO_REUSEADDR error");
		ptr= ifi->ifi_addr; // IP address
		addr = sock_ntop_host(ptr, sizeof(ptr));
		sock_info[i].ipaddr=calloc(1,strlen(addr));
		strncpy(sock_info[i].ipaddr,addr,strlen(addr));
		printf("\nIP address:%s\n", sock_info[i].ipaddr);

		ptr=ifi->ifi_ntmaddr; // Network mask
		addr = sock_ntop_host(ptr,sizeof(ptr));
		sock_info[i].ipmask=calloc(1,strlen(addr));
		strncpy(sock_info[i].ipmask,addr,strlen(addr));
		printf("Network mask:%s\n", sock_info[i].ipmask);

		strncpy(tempaddr,sock_info[i].ipaddr,strlen(sock_info[i].ipaddr));
		ip = strtok_r(tempaddr,token,&ptr1);


		strncpy(tempmask,sock_info[i].ipmask,strlen(sock_info[i].ipmask));
		netmask = strtok_r(tempmask, token,&ptr2);

		subnet=calloc(1,16);


		/* code to obtain the Subnet address begins */
		// Subnet address is obtained by performing a bitwise AND of the IP address and Network mask

        len=0;
		while (ip!=NULL && netmask!=NULL)
		{
			k = atoi(ip) & atoi(netmask);
			snprintf(subnet+len, 16,"%d",k);
			subnet[strlen(subnet)]='.';
			len = strlen(subnet);
			ip = strtok_r(NULL, token,&ptr1);
			netmask= strtok_r(NULL,token,&ptr2);

		}

		sock_info[i].ipsubnet=calloc(1,strlen(subnet)-1);
		strncpy(sock_info[i].ipsubnet,subnet,strlen(subnet)-1);
		fprintf(stdout,"Subnet Address:%s\n",sock_info[i].ipsubnet);

		/* code to obtain the Subnet address ends */

		/* code for binding the socket to the unicast address begins */

		sa= (struct sockaddr_in *) ifi->ifi_addr;
		sa->sin_family= AF_INET;
		sa->sin_port=htons(infile.port);
		if ((bind(sock_info[i].sockfd, (SA*) sa, sizeof(*sa))) < 0)
			err_sys("bind error");
		else
			fprintf(stdout,"\nBind successful: %s , sockfd:%d\n",sock_ntop((SA*) sa, sizeof(*sa)),sock_info[i].sockfd);

		/* code for binding the socket to the unicast address ends */

		i++;
	}
	structlen = i;	// length of array of structures

	len = 0;

	for( ; ; )
	{
		FD_ZERO( &rset);
		for( j = 0; j < structlen; j++) // all the server sockets are set to listen from the clients
		{
			FD_SET(sock_info[j].sockfd, &rset);
			if(maxfdp < sock_info[j].sockfd)
				maxfdp = sock_info[j].sockfd;
		}
		fdp1 = maxfdp + 1;
        int sval = 0;
selectagain:
		if((sval = select(fdp1, &rset, NULL, NULL, NULL)) < 0) {
            if (errno == EINTR)
                goto selectagain;
            else
		    err_sys("Select error.");
        }

		for(j = 0; j < structlen; j++)
		{
			if(FD_ISSET(sock_info[j].sockfd, &rset))
			{
				listenfd = sock_info[j].sockfd;
				clilen = sizeof(struct sockaddr_in);

                //server receives the file name from the client
				n = recvfrom( listenfd, recvline, MAXLINE, 0, (SA *) &cliaddr, &clilen);
				//--------- code to separate the filename and window size obtained from the client begins
				while(recvline[finc]!=';')
				{
				  sprintf(filename+finc,"%c",recvline[finc]);
				  finc++;
				}
				fprintf(stdout, "\nThe file name received from client is :%s \n", filename);
				cliadwin=recvline[finc+1]-'0';
				fprintf(stdout, "\nThe advertising window size of the client :%d \n", cliadwin);
				//---------code to separate the filename and window size obtained from the client ends

                char mbuf[MAXLINE];
                memset(&mbuf[0], 0, sizeof(mbuf));
                Inet_ntop(AF_INET, &cliaddr.sin_addr, mbuf, sizeof(mbuf));
                bool isretransmission = false;
                if (lptr != NULL) {
                    tptr = lptr;
                    while (tptr != NULL) {
                        if ((strncmp(tptr->ip_addr, mbuf, strlen(mbuf)) == 0) &&
                                    (tptr->port_num == ntohs(cliaddr.sin_port))) {
                            isretransmission = true;
                            break;
                        }
                        if (tptr->next != NULL)
                            tptr = tptr->next;
                        else
                            break;
                    }
                    if ( !isretransmission) {
                        ckeeper *node = (ckeeper *) calloc(1, strlen(mbuf));
                        node->pid = -1;
                        node->ip_addr = (char *) calloc(1, strlen(mbuf));
                        strncpy(node->ip_addr, mbuf, strlen(mbuf));
                        node->port_num = ntohs(cliaddr.sin_port);
                        node->next = NULL;
                        tptr->next = node;
                    }
                }
                else {
                    lptr = (ckeeper *) calloc(1, sizeof(ckeeper));
                    lptr->pid = -1;
                    lptr->ip_addr = (char *) calloc(1, strlen(mbuf));
                    strncpy(lptr->ip_addr, mbuf, strlen(mbuf));
                    lptr->port_num = ntohs(cliaddr.sin_port);
                    lptr->next = NULL;
                }

                if (isretransmission) {
                    break;
                }

				pid = fork();
				l = j;
				if (pid == 0)
				{
					for(m = 0;m < structlen; m++)
					{
					    if(m != l)
					    {
				               close(sock_info[m].sockfd);// all other listening sockets are closed
					    }
					}
				    //Check if the client is local or not; if local MSG_DONTROUTE / SO_DONTROUTE socket option for communication
				    //Print the info ( whether local or not to the stdout)
				    //Create a UDP connection socket
				    //getsockname to get the IP address and port that was assigned to the socket
                    socklen_t slen = sizeof(pservaddr);
			        Getsockname(listenfd, (SA *) &pservaddr, &slen);

					ipserv=calloc(1,strlen(sock_info[l].ipaddr));
					strncpy(ipserv,sock_info[l].ipaddr,strlen(sock_info[l].ipaddr));
			        fprintf(stdout,"\nThe IP address of the server, IPServer :%s\n",ipserv);

			        ipclient=calloc(1, clilen);
			        strncpy(ipclient,sock_ntop_host((SA *) &cliaddr, sizeof(cliaddr)), clilen);
                    cli_port = ntohs(cliaddr.sin_port);
			        fprintf(stdout,"\nThe IP address of the client, IPClient :%s\n",ipclient);
                    printf("\nClient port number: %d\n", ntohs(cliaddr.sin_port));

			        /* code to check if the client is local to the server*/
			        if(strncmp(ipserv,localhost,strlen(ipserv))==0) {
			            fprintf(stdout,"\nThe server address is the loopback address.");
			            str_client(listenfd, ipserv, ipclient, cli_port, filename,cliadwin,infile.w_size);
			        }
			        else { // server address is not the loopback addr
                        tempcli=(char *)calloc(1,strlen(ipclient));
                        strncpy(tempcli,ipclient,strlen(ipclient));
                        clitok=strtok_r(tempcli,token,&ptr3);
                        servmask=(char *)calloc(1,strlen(sock_info[l].ipmask));
                        strncpy(servmask,sock_info[l].ipmask,strlen(sock_info[l].ipmask));
                        servtok=strtok_r(servmask,token,&ptr4);
                        len = 0;
                        tservaddr=(char *) calloc(1,16);

                        while(clitok!=NULL && servtok!=NULL) {
                            q= atoi(clitok) & atoi(servtok);
                            snprintf(tservaddr+len,16,"%d",q);
                            tservaddr[strlen(tservaddr)]='.';
                            len=strlen(tservaddr);
                            clitok=strtok_r(NULL,token,&ptr3);
                            servtok=strtok_r(NULL,token,&ptr4);
                        }
                        servaddr=(char*) calloc(1,strlen(tservaddr));
                        strncpy(servaddr,tservaddr,strlen(tservaddr)-1);
                        fprintf(stdout,"\nThe client network address is: %s\n",servaddr);
                        fprintf(stdout,"\nThe server and client are in the same network.\n");
                        if(strncmp(servaddr,sock_info[l].ipsubnet,strlen(sock_info[l].ipsubnet))==0) {
                            if(setsockopt(listenfd,SOL_SOCKET,SO_DONTROUTE,&on,sizeof(on))<0)
                                err_sys("setsocket option:SO_DONTROUTE error.");
                            else
                                fprintf(stdout,"\nThe SO_DONTROUTE option is set.\n");
                        }
                        str_client(listenfd, ipserv, ipclient, cli_port,filename, cliadwin,infile.w_size);
                        //fprintf(stdout,"\nFinished three way handshake with the client.\n");

					}
					len++;
					close(listenfd);
				}
                if ( !isretransmission) {
                    tptr = lptr;
                    while (tptr->next)
                        tptr = tptr->next;
                    tptr->pid = pid;
                }
			}
		}
	}
	exit(0);
}

void str_client(int lsock,char *ipserver,char *ipcli, uint16_t port, char filename[], int cliadwin, int servadwin)
{
	int listenfd, connfd, len;
	struct sockaddr_in sa, addrptr, pcliaddr;
	char portbuffer[MAXLINE],*ptr, mbuf[MAXLINE],clibuffer[MAXLINE];
    struct itimerval timer;

	if((connfd=socket(AF_INET,SOCK_DGRAM,0))<0) // new "connection" socket for the child process
		err_sys("Conn socket error");

	bzero(&sa, sizeof(sa));
	//fprintf(stdout,"Inside 127.0.0.1...before inet_pton\n");
	if((inet_pton(AF_INET,ipserver,&sa.sin_addr))<0) // Converting the server IP address in dotted decimal to network address
		err_sys("inet_pton error.");
	//fprintf(stdout,"Inside 127.0.0.1...after inet_pton\n");
	sa.sin_family= AF_INET;
	sa.sin_port=htons(0);
	if((bind(connfd,(SA*) &sa, sizeof(sa)))<0) // binding to an ephemeral port
		err_sys("bind error");
	len=sizeof(addrptr);
	//addrptr=malloc(sizeof(struct sockaddr_in));
	if((getsockname(connfd,(SA *) &addrptr,&len))<0)
		err_sys("getsockname error");
    printf("\nAfter bind: \n");
	printf("Server IP address: %s\n", Inet_ntop(AF_INET, &addrptr.sin_addr, mbuf, sizeof(mbuf)));
    printf("Server port number: %d\n", ntohs(addrptr.sin_port));

    bzero(&pcliaddr, sizeof(pcliaddr));
    pcliaddr.sin_family = AF_INET;
    pcliaddr.sin_port = htons(port);
    Inet_pton(AF_INET, ipcli, &pcliaddr.sin_addr);
    Connect(connfd, (SA *) &pcliaddr, sizeof(pcliaddr));

	snprintf(portbuffer,MAXLINE,"%d",addrptr.sin_port);
	// to send the server window along with port number
	int portlen=strlen(portbuffer);
	sprintf(portbuffer+portlen,";%d",servadwin);
    socklen_t clen = sizeof(pcliaddr);
	sendto( lsock, portbuffer, strlen(portbuffer), 0, (SA *) &pcliaddr, clen);
	fprintf(stdout,"\nSending port number %d to client: %s\n", port, ipcli);
    timer.it_value.tv_sec=0;
    timer.it_value.tv_usec=INTERVAL*1000;
    timer.it_interval.tv_sec=0;
    timer.it_interval.tv_usec=INTERVAL*1000;
    if((setitimer(ITIMER_REAL,&timer,NULL))<0)
        err_sys("Error setting the timer.");

label:
    if((recvfrom(connfd,clibuffer , MAXLINE, 0, NULL,NULL)) < 0) {
        if(errno == EINTR) {
            fprintf(stdout,"socket timeout: did not receive the acknowledgement of the port number from the client.");
            Sendto( lsock, portbuffer, strlen(portbuffer), 0, (SA *) &pcliaddr, clen);
            fprintf(stdout,"\nSent the port number: %s from listening socket :%d",portbuffer,lsock);
            Sendto(connfd, portbuffer, strlen(portbuffer), 0, (SA *) &pcliaddr, clen);
            fprintf(stdout,"\nSent the port number: %s from connection socket :%d",portbuffer,connfd);
            goto label;
        }
        else
            err_sys("recvfrom error.");
    }

	fprintf(stdout," \nReceived acknowledgement from the client.\n");
    printf("\nThree way handshake is complete.\n \n");
    timer.it_value.tv_sec=0;
    timer.it_value.tv_usec=0;
    timer.it_interval.tv_sec=0;
    timer.it_interval.tv_usec = 0;
    if((setitimer(ITIMER_REAL,&timer,NULL))<0)
        err_sys("Error setting the timer.");
	close(lsock);
    send_datagram(connfd,filename, cliadwin,servadwin);
    close(connfd);
    printf("\nChild process with pid %d is terminated. \n", getpid());
	exit(0);
}

static sigjmp_buf jmpbuf;


static int seq = 0;
static int left = 0, right = 0;
static struct msghdr msgsend = {} , msgrecv = {};
struct rtt_info rttinfo;
//int rtt_d_flag = 0;
static int rttinit = 0;

void send_datagram(int sockfd,char filename[], int cliwindow, int servwindow)
{
    ssize_t nbytes, n;
    int sec = 0;
    int usec = 0, ti =0;
    FILE *fp;
    int index = 0;
    int payload = PAYLOAD - sizeof(struct hdr);
    char sbuff[payload];
    datagram *senddg = (char *) calloc(servwindow, sizeof(struct datagram));
    int ssthresh = cliwindow;
    int ad_window = cliwindow;
    int win_size = servwindow;
    int cwnd = 1;
    int it = 0, reseq = 0;
    int currack = 0, dupack = 0;
    bool slowstart = true;
    bool congavoid = false;

    struct itimerval timer;
    //struct hdr sendhdr = {}, recvhdr = {};
    struct iovec iovsend[2], iovrecv[1];
    bool endf = false;

    fp=fopen(filename,"r");
    if (fseek(fp, SEEK_SET, 0) != 0)
        err_sys("fseek error");

    while ( 1 ) {
        //rttinit = 0;
        it = 0;
        left = currack;
        if (endf && (left == right)) {
            printf("\nData transfer to the client is done.\n");
            break;
        }
        //if (currack < right)///
        for( ; it < cwnd; it++) {
           // printf("index is: %d\n", index);
            if (left < right) {
                index = left % win_size;
                sendhdr.seq= senddg[index].header.seq;
                left++;
            }
            else {
                if (endf)
                    break;
                index = right % win_size;
                //for (st = 0; st < payload, st++)

                memset(&senddg[index].buffer[0], 0, sizeof(senddg[index].buffer));
                if ((nbytes = fread(senddg[index].buffer, payload, 1, fp)) <= 0) {
                    if (feof(fp)) {
                        endf = true;
                    }
                    else
                        err_sys("fread error");
                }
                //senddg[index].buffer[strlen(senddg[index].buffer)] = 0;
                sendhdr.seq= seq++;
                senddg[index].header.seq = sendhdr.seq;
                right++;
                left++;
            }
            if (rttinit == 0) {
                rtt_init(&rttinfo);
                rttinit = 1;
                //rtt_d_flag = 1;
            }
            memset(&sbuff[0], 0, sizeof(sbuff));
            strncpy(sbuff, senddg[index].buffer, strlen(senddg[index].buffer));
            sendhdr.ack = 0;
            sendhdr.adv_window = servwindow;
            msgsend.msg_name = NULL;
            msgsend.msg_namelen = 0;
            msgsend.msg_iov = iovsend;
            msgsend.msg_iovlen = 2;
            iovsend[0].iov_base = &sendhdr;
            iovsend[0].iov_len = sizeof(struct hdr);
            iovsend[1].iov_base = sbuff;
            iovsend[1].iov_len = strlen(sbuff);

            signal(SIGALRM, sig_alrm);
            rtt_newpack(&rttinfo);

            //left++;
            sendhdr.ts = rtt_ts(&rttinfo);
            fprintf(stdout,"Sending data with sequence number : %d\n",sendhdr.seq);
            fprintf(stdout, "cwindow: %d\n", cwnd);
            fprintf(stdout, "ssthresh: %d\n", ssthresh);
            if (sendmsg(sockfd, &msgsend, 0) < 0) {
                err_sys("sendmsg error");
            }
        }
        fprintf(stdout, "\nLast datagram in flight is with sequence number: %d\n", sendhdr.seq);
        ti = rtt_start(&rttinfo);
        timer.it_value.tv_sec = ti / 1000;
        timer.it_value.tv_usec = (ti % 1000) * 1000;
        timer.it_interval.tv_sec = 0;
        timer.it_interval.tv_usec = 0;
        setitimer(ITIMER_REAL, &timer, NULL);
        //alarm(ti / 1000);
        //printf("seconds to sleep: %d\n", ti);
        printf ("\nRTO: %d millisecs.\n", ti);

        if (sigsetjmp(jmpbuf, 1) != 0) {
            if (rtt_timeout(&rttinfo) < 0) {
                err_msg("no response from the client, giving up");
                rttinit = 0;
                errno = ETIMEDOUT;
                exit(0);
            }
            printf("\nTimeout happened for datagram with sequence number: %d\n", senddg[currack % win_size].header.seq);
            printf("\nStarting slow start:\n");
            sendagain(senddg[currack % win_size].header.seq, sockfd, senddg[currack % win_size].buffer);
            ti = rtt_start(&rttinfo);
            timer.it_value.tv_sec = ti / 1000;
            timer.it_value.tv_usec = (ti % 1000) * 1000;
            setitimer(ITIMER_REAL, &timer, NULL);
            printf ("\nRTO: %d millisecs.\n", ti);
            cwnd = 1;
            ssthresh = ((cwnd /2) > 2) ? (cwnd / 2) : 2;
            slowstart = true;
            congavoid = false;
        }

        while ( currack < right) {

	        msgrecv.msg_name = NULL;
            msgrecv.msg_namelen = 0;
            msgrecv.msg_iov = iovrecv;
            msgrecv.msg_iovlen = 2;
            iovrecv[0].iov_base = &recvhdr;
            iovrecv[0].iov_len = sizeof(struct hdr);
            do{
                n = recvmsg(sockfd, &msgrecv, 0);
                if (n < 0)
                    err_sys("recvmsg error:");
            } while (n < sizeof(struct hdr));
            fprintf(stdout,"\nAcknowledgement from client: %d \nAdv window of client:  %d\n", recvhdr.ack, recvhdr.adv_window);
            ad_window = recvhdr.adv_window;
            if (currack == recvhdr.ack) {
                dupack++;
                printf("Ack %d is duplicate.\n", currack);
                if (dupack >= 3) {
                    fprintf(stdout, "Ack %d is coming for >=3rd time\n", currack);
                    printf("\nFast retransmission\n");
                    dupack = 0;
                    cwnd /= 2;
                    ssthresh = (cwnd >= 2) ? cwnd : 2;
                    congavoid = true;
                    slowstart = false;
                    break;
                }
            }
            else {
                currack = recvhdr.ack;
                dupack = 1;
                fprintf(stdout, "Cwin and ssthresh: %d , %d \n", cwnd, ssthresh);
            }
        }
        //printf("\nCwin and ssthresh: %d , %d \n", cwin, ssthresh);
        timer.it_value.tv_sec = 0;
        timer.it_value.tv_usec = 0;
        timer.it_interval.tv_sec = 0;
        timer.it_interval.tv_usec = 0;
        setitimer(ITIMER_REAL, &timer, NULL);
        rtt_stop(&rttinfo, rtt_ts(&rttinfo) - recvhdr.ts);
        if (ad_window == 0) {
            printf("\nAdv window of client is 0. Waiting for adv window update\n");
            ad_window = recvagain(sockfd);
        }
        if (slowstart) {
            cwnd *= 2;
            cwnd = (cwnd <= ad_window) ? cwnd : ad_window;
            if (cwnd >= ssthresh) {
                slowstart = false;
                congavoid = true;
            }
            left = right;
        }
        else if (congavoid) {
            cwnd += 1;
            cwnd = (cwnd <= ad_window) ? cwnd : ad_window;
            if (cwnd < ssthresh) {
                slowstart = true;
                congavoid = false;
            }
        }
        fprintf(stdout, "Cwin and ssthresh: %d , %d \n", cwnd, ssthresh);
    }
}

void sendagain(int seq, int sockfd, char *buffer) {
    int payload = PAYLOAD - sizeof(struct hdr);
    char sbuff[payload];
    struct iovec iovsend[2];
    strncpy(sbuff, buffer, strlen(buffer));
    sendhdr.seq= seq;
    sendhdr.ack = 0;
    sendhdr.adv_window = 0;
    msgsend.msg_name = NULL;
    msgsend.msg_namelen = 0;
    msgsend.msg_iov = iovsend;
    msgsend.msg_iovlen = 2;
    iovsend[0].iov_base = &sendhdr;
    iovsend[0].iov_len = sizeof(struct hdr);
    iovsend[1].iov_base = sbuff;
    iovsend[1].iov_len = payload;
    sendhdr.ts = rtt_ts(&rttinfo);
    fprintf(stdout,"\nRetrasmmitting the datagram with Sequence number: %d\n",sendhdr.seq);
    if (sendmsg(sockfd, &msgsend, 0) < 0) {
        err_sys("sendmsg error");
    }
}

int recvagain(int sockfd) {

        //char rbuff[PAYLOAD];
        size_t n;
    //int index
    struct iovec iovrecv[2];
	        msgrecv.msg_name = NULL;
            msgrecv.msg_namelen = 0;
            msgrecv.msg_iov = iovrecv;
            msgrecv.msg_iovlen = 2;
            iovrecv[0].iov_base = &recvhdr;
            iovrecv[0].iov_len = sizeof(struct hdr);
            //iovrecv[1].iov_base = rbuff;
            //iovrecv[1].iov_len = PAYLOAD;
recvagain:
            do{
                n = recvmsg(sockfd, &msgrecv, 0);
                if (n < 0)
                    err_sys("recvmsg error:");
            } while (n < sizeof(struct hdr));
        fprintf(stdout,"\nAcknowledgement from client: ack window %d %d\n", recvhdr.ack, recvhdr.adv_window);
        return recvhdr.adv_window;

}

static void sig_alrm(int signo) {
    siglongjmp(jmpbuf, 1);
}
