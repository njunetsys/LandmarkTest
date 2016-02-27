CC	= gcc
CFLAGS	= -Wall
LIBSTHREAD = -lpthread
LIBSNETFILTER = -lnfnetlink -lnetfilter_queue

sender_client_tcp : sender_client_tcp.o failure_detection.o
	$(CC) sender_client_tcp.o failure_detection.o -o sender_client_tcp $(LIBSTHREAD) $(LIBSNETFILTER)
	
receiver_client_tcp : receiver_client_tcp.o
	$(CC) receiver_client_tcp.o -o receiver_client_tcp $(LIBSNETFILTER)
	
sender_client_multiproto : sender_client_multiproto.o failure_detection.o
	$(CC) sender_client_multiproto.o failure_detection.o -o sender_client_multiproto $(LIBSTHREAD) $(LIBSNETFILTER)
	
sender_client_multiproto_isfailure : sender_client_multiproto_isfailure.o failure_detection.o
	$(CC) sender_client_multiproto_isfailure.o failure_detection.o -o sender_client_multiproto_isfailure $(LIBSTHREAD) $(LIBSNETFILTER)	

receiver_client_multiproto : receiver_client_multiproto.o failure_detection.o
	$(CC) receiver_client_multiproto.o failure_detection.o -o receiver_client_multiproto $(LIBSTHREAD) $(LIBSNETFILTER)

landmark : landmark.o
	$(CC) landmark.o -o landmark $(LIBSNETFILTER)
	
landmark.o : landmark.c
	$(CC) -c -g landmark.c	

sender_client_tcp.o : sender_client_tcp.c
	$(CC) -c -g sender_client_tcp.c
	
receiver_client_tcp.o : receiver_client_tcp.c
	$(CC) -c -g receiver_client_tcp.c

sender_client_multiproto.o : sender_client_multiproto.c
	$(CC) -c -g sender_client_multiproto.c
	
sender_client_multiproto_isfailure.o : sender_client_multiproto_isfailure.c
	$(CC) -c -g sender_client_multiproto_isfailure.c

receiver_client_multiproto.o : receiver_client_multiproto.c
	$(CC) -c -g receiver_client_multiproto.c

detection_test : detection_test.o failure_detection.o
	$(CC) detection_test.o failure_detection.o -o detection_test $(LIBSTHREAD)

detection_test.o : detection_test.c
	$(CC) $(CFLAGS) -c -g detection_test.c

failure_detection.o : failure_detection.h failure_detection.c
	$(CC) $(CFLAGS) -c -g failure_detection.c
	
clean:
	rm *.o
