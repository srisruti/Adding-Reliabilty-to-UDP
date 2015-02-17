#include "unpifiplus.h"
#include <sys/time.h>
#include <stdbool.h>
#include <pthread.h>
#include <math.h>

extern struct ifi_info *get_ifi_info_plus(int family, int doaliases);
extern void free_ifi_info_plus(struct ifi_info *ifihead);

#define MAXLEN 180
#define PAYLOAD 512
#define INTERVAL 500 //in milliseconds
#define EVAL 2.718281

//bool ackt = false;
pthread_mutex_t mutex =PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t cond_var = PTHREAD_COND_INITIALIZER;
static void *consume(void *);
void read_from_server(int sockfd, int w);

typedef struct input_text {
    char *ip_addr;
    int port_num;
    char *f_name;
    int s_window;
    int seed;
    float p_loss;
    int mean_u;
}input_t;

input_t text_f;

struct hdr {
    uint32_t seq;
    uint32_t ack;
    int adv_window;
    uint32_t ts;
};

typedef struct datagram {
    struct hdr header;
    char buffer[PAYLOAD - sizeof(struct hdr)];
} datagram;

datagram *recvdg;

static int window = 0;
static int rightseq = 0, leftseq = 0;

static void sig_alrm(int signo)
{
	return;
}

int countsetbits(int n)
{
    unsigned int count = 0;
    while (n) {
        n &= (n-1) ;
        count++;
    }
    return count;
}

void read_input_file( input_t *it) {

    char rbuff[7][MAXLEN];
    FILE *fp;
    int index = 0;
    if ((fp = fopen("client.in", "r")) == NULL)
        err_sys("fopen error.");
    while ((fgets(rbuff[index], MAXLEN, fp) != NULL) && (index < 7)) {
        index++;
    }
    if (index < 7)
        err_sys("insufficient information in client.in file.");

    it->ip_addr = calloc(1, strlen(rbuff[0]) - 1);
    strncpy(it->ip_addr, rbuff[0], strlen(rbuff[0]) - 1);
    it->port_num = (uint16_t) atoi(rbuff[1]);
    it->f_name = calloc(1, strlen(rbuff[2]) - 1);
    strncpy(it->f_name, rbuff[2], strlen(rbuff[2]) - 1);
    it->s_window = atoi(rbuff[3]);
    it->seed = atoi(rbuff[4]);
    it->p_loss = atof(rbuff[5]);
    it->mean_u = atoi(rbuff[6]);
    fclose(fp);
}

int is_local_addr(char *serv_addr, char **cli_addr) {
    struct sockaddr *ptr, *cliaddr;
    struct ifi_info *ifi, *head;
    socklen_t clilen;
    char *ipserv,*ipclient;
    const int on=1;
    char *ptr1, *ptr2, *ptr3, *ip, *mask, *saddr;
    char *addr;
    const char token[2]=".";
    int cnetprefix = 0, snetprefix = 0;
    int clen, slen, count = 0, rand_index, index, localnode = -1, islocal = 0;
    char *cIP[20];
    int lpmatch = 0, bit = 0;

	if ((head = ifi = get_ifi_info_plus(AF_INET, 1)) == NULL) // to get all the IP addresses of the client
		err_sys("get_ifi_info error");

    printf ("\nClient Interface details:\n");
	for( ; ifi != NULL; ifi = ifi->ifi_next) // looping through the ifi_info structure
	{
       bit = 0;

	    char *ipaddr = NULL, *netmask = NULL, *netaddr = NULL, *servaddr = NULL;
        char ipaddrcpy[16], netmaskcpy[16], servaddrcpy[16];

	    ptr = ifi->ifi_addr; // IP address
	    addr = sock_ntop_host(ptr, sizeof(ptr));
	    ipaddr = (char *)calloc(1, strlen(addr));
        cIP[count] = (char *)calloc(1, strlen(addr));
        strncpy(ipaddr, addr, strlen(addr));
        if (ipaddr == NULL)
            goto free_memory;

	    strncpy( cIP[count], addr, strlen(addr));
        if (strlen(ipaddr) == strlen(serv_addr))
            if (strncmp(ipaddr, serv_addr, strlen(serv_addr)) == 0)
                islocal = 1;
        count++;
		printf("\nIP address:%s\n", ipaddr);

		ptr = ifi->ifi_ntmaddr; // Network mask
		addr = sock_ntop_host(ptr,sizeof(ptr));
	    netmask = (char *)calloc(1, strlen(addr));
        if (netmask == NULL)
            goto free_memory;
		strncpy(netmask, addr, strlen(addr));
		printf("Network mask:%s\n", netmask);

        if (islocal != 1) {

		    strncpy(ipaddrcpy, ipaddr,strlen(ipaddr));
		    ip = strtok_r(ipaddrcpy, token, &ptr1);

		    strncpy(netmaskcpy, netmask, strlen(netmask));
		    mask = strtok_r(netmaskcpy, token, &ptr2);

            strncpy(servaddrcpy, serv_addr, strlen(serv_addr));
            saddr = strtok_r(servaddrcpy, token, &ptr3);

            netaddr = (char *)calloc(1, strlen(ipaddr));
			servaddr = (char *)calloc(1, strlen(serv_addr));

		    /* code to obtain the Subnet address of the client begins */
		    // Subnet address is obtained by performing a bitwise AND of the IP address and Network mask
		    clen = 0, slen = 0;
		    while ((ip != NULL && mask != NULL) && saddr != NULL) {
		        cnetprefix = atoi(ip) & atoi(mask);
				snetprefix = atoi(saddr) & atoi(mask);
                snprintf(netaddr + clen, strlen(ipaddr),"%d", cnetprefix);
				netaddr[strlen(netaddr)]='.';
				clen = strlen(netaddr);
				snprintf(servaddr + slen, strlen(serv_addr),"%d", snetprefix);
				servaddr[strlen(servaddr)]='.';
				slen = strlen(servaddr);
				ip = strtok_r(NULL, token, &ptr1);
				mask = strtok_r(NULL, token, &ptr2);
				saddr = strtok_r(NULL, token, &ptr3);
                bit += 8;
			}
            bit = bit - 8 + countsetbits(cnetprefix);
			netaddr[strlen(netaddr) - 1] = 0;
			servaddr[strlen(servaddr) - 1] = 0;
            // to check if the client and server are on the same network
			if (strlen(netaddr) == strlen(servaddr)) {
				if (strncmp(netaddr, servaddr, strlen(servaddr)) == 0) {
                    if (lpmatch < bit) {
                        lpmatch = bit;
				        localnode = count - 1;
                    }
                }
            }
        }
free_memory:
        free(ipaddr);
        free(netmask);
        free(netaddr);
        free(servaddr);
	}
    if (islocal == 1) {
        *cli_addr = NULL;
        for ( index = 0; index < count; index++)
            free(cIP[index]);
        free(head);
        return 1;
    }
    else if (localnode != -1) {
        *cli_addr = (char *) calloc(1, strlen(cIP[localnode]));
        strncpy(*cli_addr, cIP[localnode], strlen(cIP[localnode]));
        printf("\nClient IP %s is on same network with server.\n", *cli_addr);
    }
    else {
        rand_index = rand() % count;
        if (rand_index == 0)
            rand_index = count - 1;
        *cli_addr = (char *) calloc(1, strlen(cIP[rand_index]));
        strncpy(*cli_addr, cIP[rand_index], strlen(cIP[rand_index]));
    }
    for ( index = 0; index < count; index++)
        free(cIP[index]);
    free(head);
    return 0;
}


int establish_connection(int sockfd, const SA *pservaddr, socklen_t servlen, char* filename,int cliadwin)
{
	int n;
    socklen_t len;
    struct sockaddr_in servaddr,newservaddr;
	char sendline[MAXLINE], recvline[MAXLINE+1],recvport[MAXLINE],recvfile[MAXLINE];
	char mbuf[MAXLINE],ack[MAXLINE],portbuf[MAXLINE];
	char servbuf[MAXLINE];
	int pinc=0;
	int servadwin=0; // server advertising window
	strncpy(sendline, filename, strlen(filename));

	int filelen=strlen(filename);
	sprintf(sendline+filelen,";%d", cliadwin);
	struct itimerval timer;

 sendfileagain:
	Sendto(sockfd, sendline, strlen(sendline),0, NULL,NULL);

	fprintf(stdout,"\nSending file name and adv window to server : %s \n",sendline);

    timer.it_value.tv_sec=0;
    timer.it_value.tv_usec=INTERVAL*1000;
    timer.it_interval.tv_sec=0;
    timer.it_interval.tv_usec=INTERVAL*1000;

   if((setitimer(ITIMER_REAL,&timer,NULL))<0)
        err_sys("Error setting the timer.");

    len=sizeof(servaddr);
	if((n=recvfrom(sockfd, recvline, MAXLINE, 0,(SA*) &servaddr,&len))<0) {
		if(errno==EINTR) {
			fprintf(stdout,"socket timeout: new port number from the server not received.\n");
			goto sendfileagain;
		}
		else
            err_sys("recvfrom error");
	}
	//----------- To get the server advertisement starts--------//
	while(recvline[pinc]!=';')
	{
		sprintf(recvport+pinc,"%c",recvline[pinc]);
		pinc++;
	}
	fprintf(stdout, "The new port number received from server is :%s \n", recvport);
	servadwin=recvline[pinc+1]-'0';
	//----------- To get the server advertisement ends--------//

    Inet_ntop(AF_INET, &servaddr.sin_addr, mbuf, sizeof(mbuf));
	bzero(&newservaddr,sizeof(newservaddr));
	newservaddr.sin_family=AF_INET;
	newservaddr.sin_port=htons((uint16_t)atoi(recvport));
	Inet_pton(AF_INET, mbuf, &newservaddr.sin_addr);
	Connect(sockfd,(SA*) &newservaddr,sizeof(newservaddr));
	fprintf(stdout,"Connected to the server %s with new port. %d\n",mbuf,ntohs(newservaddr.sin_port));
	strcpy(ack,"Received the port number.");
	strncpy(sendline, ack, strlen(ack));
	fprintf(stdout, "Sending the acknowledgement to the server.\n");
	Sendto(sockfd, sendline, strlen(sendline), 0, NULL, NULL);
	timer.it_value.tv_sec=0;
    timer.it_value.tv_usec=0;
    timer.it_interval.tv_sec=0;
    timer.it_interval.tv_usec=0;

   if((setitimer(ITIMER_REAL,&timer,NULL))<0)
        err_sys("Error setting the timer.");
    return sockfd;
}


int main(int argc, char* argv[])
{
	int sockfd,local;
	struct sockaddr_in servaddr, cliaddr, pcliaddr, pservaddr;
    char localIP[10] = "127.0.0.1";
    char mbuf[MAXLINE];
	read_input_file((input_t *) &text_f);
    int adwindow = text_f.s_window;
    window = text_f.s_window;
    char *IPserver = NULL, *IPclient = NULL;

    if (is_local_addr(text_f.ip_addr, &IPclient)) {
        printf("\nServer and client are on local host.\n");
        IPclient = localIP;
        printf("IP address of client, IPClient: %s\n", IPclient);
        IPserver = localIP;
        printf("IP address of server, IPServer: %s\n", IPserver);
    }
    else {
        printf("\nServer and client are not on local host.\n");
        printf("IP address of client, IPClient: %s\n", IPclient);
        IPserver = text_f.ip_addr;
        printf("IP address of server, IPServer: %s\n", IPserver);
    }

	sockfd = Socket(AF_INET, SOCK_DGRAM, 0);

    bzero(&cliaddr, sizeof(cliaddr));
    cliaddr.sin_family = AF_INET;
    cliaddr.sin_port = htons(0);

    if (inet_pton(AF_INET, IPclient, &cliaddr.sin_addr) <= 0) {
        err_sys("Error in inet_pton.\n");
    }

    Bind(sockfd, (SA *) &cliaddr, sizeof(cliaddr));
    socklen_t len = sizeof(pcliaddr);

    // to obtain the IPclient and ephemeral port number
    Getsockname(sockfd, (SA *) &pcliaddr, &len);
    printf ("After bind:\n");
    printf("Client IP address: %s\n", Inet_ntop(AF_INET, &pcliaddr.sin_addr, mbuf, sizeof(mbuf)));
    printf("Client port number: %d\n", ntohs(pcliaddr.sin_port));

	bzero(&servaddr, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_port = htons(text_f.port_num);
	Inet_pton(AF_INET, IPserver, &servaddr.sin_addr);
    Connect(sockfd, (SA *) &servaddr, sizeof(servaddr));

    len = sizeof(pservaddr);
    // to obtain the IPserver and port number of the server

    Getpeername(sockfd, (SA *) &pservaddr, &len);
    printf("After connect:\n");
    printf("Server IP address: %s\n", Inet_ntop(AF_INET, &pservaddr.sin_addr, mbuf, sizeof(mbuf)));
    printf("Server port number: %d\n", ntohs(pservaddr.sin_port));

    sockfd = establish_connection(sockfd, (SA*) &servaddr, sizeof(servaddr), text_f.f_name,adwindow);
	Signal(SIGALRM,sig_alrm);
    srand(text_f.seed);
    recvdg = (char *) calloc(window, sizeof(struct datagram));
    read_from_server(sockfd, adwindow);
    close(sockfd);
	exit(0);
}


void read_from_server(int sockfd, int win) {
    int payload = PAYLOAD - sizeof(struct hdr);
    struct hdr sendhdr, recvhdr;
    char recvbuf[payload];
    int cliseq = 0;
    struct msghdr msgsend = {}, msgrecv = {};
    struct iovec iovsend[1], iovrecv[2];
    ssize_t nbytes;
    int it = 0, ack;
    float probability = 0.0;
    pthread_t tid;
    bool complete = false;
    int inbytes = payload;
    for (it = 0; it < text_f.s_window; it++) {
        recvdg[it].header.ack = 0;
    }
    if (pthread_create(&tid, NULL, &consume, NULL) < 0)
        err_sys("consumer thread creation error");
	while(1) {
        pthread_mutex_lock(&mutex);
        memset(&recvbuf[0], 0, sizeof(recvbuf));
        while (window == 0) {
            printf("\nWindow size on Receiver is zero. Waiting for consumer to free the buffer..\n");
            pthread_cond_wait(&cond_var, &mutex);
            printf("\nWindow size is non zero now. Sending acknowledgement to server with updated adv window.\n");
            sendhdr.adv_window = window;
            if (sendmsg(sockfd, &msgsend, 0) < 0)
                err_sys("sendmsg error\n");
        }

        msgrecv.msg_name = NULL;
        msgrecv.msg_namelen = 0;
        msgrecv.msg_iov = iovrecv;
        msgrecv.msg_iovlen = 2;
        iovrecv[0].iov_base = &recvhdr;
        iovrecv[0].iov_len = sizeof(struct hdr);
        iovrecv[1].iov_base = recvbuf;
        iovrecv[1].iov_len = inbytes;
receiveagain:
        if ((nbytes = recvmsg(sockfd, &msgrecv, 0)) < 0) {
            if (errno == EINTR)
                goto receiveagain;
            else
                err_sys("recvmsg error");
        }
        probability = ((float) rand() / (float) RAND_MAX);
        if (probability <= text_f.p_loss) {
            printf ("\n\nDatagram with sequence numebr %d is dropped.\n", recvhdr.seq);
            memset(&recvbuf[0], 0, sizeof(recvbuf));
            goto receiveagain;
        }
        printf("\n\nThe sequence number of received message is: %d\n", recvhdr.seq);
        printf("\nThe received message: %s \n", recvbuf);
        if (leftseq > recvhdr.seq) {
            memset(&recvbuf[0], 0, sizeof(recvbuf));
            goto receiveagain;
        }
        if (recvdg[recvhdr.seq % text_f.s_window].header.ack == 1) {
            goto sendack;
        }
        window -= 1;
        strncpy(recvdg[recvhdr.seq % text_f.s_window].buffer, recvbuf, strlen(recvbuf));
        if (strlen(recvbuf) < payload)
            complete = true;
        recvdg[recvhdr.seq % text_f.s_window].header.seq = recvhdr.seq;
        recvdg[recvhdr.seq % text_f.s_window].header.ack = 1;
        recvdg[recvhdr.seq % text_f.s_window].header.ts = recvhdr.ts;
        recvdg[recvhdr.seq % text_f.s_window].header.adv_window = 0;
        rightseq = (rightseq > recvhdr.seq) ? rightseq : recvhdr.seq;
sendack:
        ack = leftseq;
        it = leftseq;
        for ( ; it <= rightseq; it++) {
            if (recvdg[it % text_f.s_window].header.ack)
                ack = it + 1;
            else {
                break;
            }
        }
        probability = ((float) rand() / (float) RAND_MAX);
        if (probability <= text_f.p_loss) {
            printf ("\n\nAcknowledge with ack %d is lost.\n", ack);
            memset(&recvbuf[0], 0, sizeof(recvbuf));
            ack = leftseq;
            goto receiveagain;
        }

        sendhdr.seq = cliseq++;
        sendhdr.ack = ack;
        sendhdr.adv_window = window;
        sendhdr.ts = recvdg[ack - 1].header.ts;
        msgsend.msg_name = NULL;
        msgsend.msg_namelen = 0;
        msgsend.msg_iov = iovsend;
        msgsend.msg_iovlen = 2;
        iovsend[0].iov_base = &sendhdr;
        iovsend[0].iov_len = sizeof(struct hdr);

        if (sendmsg(sockfd, &msgsend, 0) < 0)
            err_sys("sendmsg error");
        pthread_mutex_unlock(&mutex);
        if (complete && (rightseq == ack - 1)) {
            printf("\nDatagram receive is complete in receiver thread.\n");
            break;
        }

    }
    pthread_join(tid, NULL);
    return ;
}


static void *consume(void *arg) {
    int it = 0;
    int payload = PAYLOAD - sizeof(struct hdr);
    bool complete = false;
    int timefd1 = 0;
    fd_set timeset;
    struct timeval tv;
    int sleep_time = 0;
    int mean = text_f.mean_u;
    float udv = ((float)rand()) / ((float) RAND_MAX);
    float logval = log(udv);
    float var = (-1.0) * (logval);
    float temp = var * (float)mean;
    sleep_time = (int)temp;
    tv.tv_sec = sleep_time / 1000;
    tv.tv_usec = (sleep_time % 1000) * 1000;
    FD_ZERO(&timeset);
    FD_SET(NULL, &timeset);

    while (1) {
        Select(timefd1, &timeset, NULL, NULL, &tv);
        pthread_mutex_lock(&mutex);
        it = leftseq;
        fprintf(stdout, "%s", "\nPrinting the Received datagram in consumer thread:\n\n");
        for ( ; it <= rightseq; it++) {
            if (recvdg[it % text_f.s_window].header.ack == 0)
                break;
            if (strlen(recvdg[it % text_f.s_window].buffer) < payload)
                complete = true;
            fprintf(stdout, "%s\n",recvdg[it % text_f.s_window].buffer);
            recvdg[it % text_f.s_window].header.ack = 0;
            memset(&recvdg[it % text_f.s_window].buffer[0], 0, sizeof(recvdg[it % text_f.s_window].buffer));
            window += 1;
        }
        leftseq = it;
        pthread_cond_signal(&cond_var);
        pthread_mutex_unlock(&mutex);
        udv = ((float)rand()) / ((float) RAND_MAX);
        logval = log(udv);
        var = (-1.0) * logval;
        temp = var * (float)mean;
        sleep_time = (int)temp;
        tv.tv_sec = (sleep_time) / 1000;
        tv.tv_usec = (sleep_time % 1000) * 1000;
        if (complete) {
            printf("File printing is done by consumer thread.\n");
            break;
        }
    }
    return;
}
