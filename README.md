						CSE533-NETWORK PROGRAMMING
						    ASSIGNMENT-2
				
Group Members:

Ashish Kumar Singh : (109952703)
Sri Sruti Mandadapu: (109749215)



PART1
=====

To ensure that only the unicast addresses, including the loopback back address, the part of code in Figure 22.17 which checks if the interface has broadcast addresses, if so, creates a new socket and binds to the broadcast addresses, was not implemented.

To maintain the information for each socket which binds to each interface of a node(server/client),the method below was followed:

1. A structure, struct_sock, was created which contains socket decriptor, IPAddress, Network Mask and Subnet Address as members.
2. An array of the above structure is created, each element of which stores all information regarding the socket.
3. As the ifi_info structure is looped, the members of the structure are assigned values,the socket file descriptor for each socket that is created, corresponding IPAddress, Network Mask and the calculated Subnet Addresses.


PART2
=====
Modifications to the code of Section 22.5

I. The header file,unprtt.h, is modified as follows:

1. The datatypes of the members of structure, rtt_info, are modified from float to int as below:

struct rtt_info {
    int rtt_rtt;
    int rtt_srtt;
    int rtt_rttvar;
    int rtt_rto;
    int rtt_nrexmt;
    uint32_t rtt_base;
};

2. The RTT_RXTMIN is set to 1000(msecs) ,RTT_RXTMAX is set to 3000(msecs) and RTT_MAXNREXMT is set to 12, for a maximum of 12 retransmissions.

3. The value of RTO, obtained in the function rtt_timeout,is passed to the rtt_minmax function to set the lower and upper bounds for the RTO value to 1000 msecs and 3000 msecs respectively.

Reliabale data transmission using ARQ-windows,with Fast-Retransmit:

1. The client sends an acknowledgement for every datagram it receives from the server. 
2. If a datagram is lost and client receives datagram having higher sequence number than the lost datagram,  the client will send an acknowledgement to the server with sequence number equal to the sequence number of the datagram which was lost.
3. If the server receives the same acknowledgement 3 times, then it will re-transmit the data corresponding to the sequence number it received in the ACK, without waiting to get timed out.
4. The client might have received other datagrams which are sent after the lost datagram. So, it will leave a space in its buffer for the datagram and places it in its position when it arrives later to ensure the data are in order.   


Flow Control via receiver sliding window advertisements:

1. The client sends the server its advertising window size along with the name of the file it wants to read during the first handshake with the server.
2. As it receives the file contents from the server, it places them into the receiving buffer and it acknowledges the receipt of data to the server along with the remaining space in its buffer. 
3. The client wil send acknowledgement with window size 0 when the application does not read from the client's receiving buffer and the buffer is full.
3. The server keeps checking the advertising window value that the client is sending. When it receives an acknowledgement with advertising window size 0, it will not send any more data to the client and waits for the client to acknowledge with a new window update ( i.e. the non zero advertised window).

Congestion Control Mechanism and Slow Start:

1. The congestion window size, cwnd, is set to 1 initially. The minimum of the values cwnd and clients's advertising window is calculated,  which determines how many datagrams need to be sent to the client.
2. First, one datagram is send to the client. When the server receives the acknowledgement,the cwnd value is incremented and again a minimum is calculated and the process repeats.
3. When the server receives an acknowledgement from the client asking for the same sequence number 3 times,it will retransmit the data .In this case the value of cwnd and sshthresh are reduced by half(ssthresh is never less than 2).
4. If the server keeps timing out for 12 times and still does not get any acknowledgement from the client, it will set the value of cwnd to 1 and ssthresh value is reduced by half.


Senders notification regarding the last datagram implementation:

1. It is checked on the client side if the received datagram is of size less than PAYLOAD. If so,  the remaining datagrams which were lost are received and once all the datagram are received, an acknowledgement is sent to the server acknowledging that all the data is received and then close. 
2. On the server side, when the server child process receives acknowledgement for the last datagram, the socket is closed and the child process corresponding to the server will terminate.


 





