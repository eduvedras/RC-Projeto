#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include "user.h"

int fd, fd2, errcode;
ssize_t n;
socklen_t addrlen;
struct addrinfo hints, hints2, *res, *res2;
struct sockaddr_in addr;
char buffer[BUFFERSIZE];
int errno;

User u;

int main(int argc, char** argv)
{
	char name_cmd[MAXCMD];
	int cmd;
	char current_GID[GIDSIZE] = "";
	char* msg;
	char gid[GIDSIZE];
	char temp[MAXGNAME];
	char mid[5];
	int ext=0;
	int firstexec;
	char gmsg[MAXGROUPSMSG];
	char* txt;
	char* fname;
	char* fdatasize;
	char tempUID[UIDSIZE];
    char tempPW[MAXPW];
	char auxc;
	char msg_no[3];
	char* tsize;
	int spaces,fsize,isInText,isFile,bufferCounter,aux,size;
	FILE *ptr;
	struct stat st = {0};

	u = processInput(argc, argv);

	initUDP();

	while(1){
		scanf("%s", name_cmd);

		cmd = getCommand(name_cmd);
		bzero(buffer,BUFFERSIZE);

		switch(cmd){
			case -1:
				write(1,"Invalid command\n",16);
				break;

			case 0: // Command: reg UID pass
				msg=(char*)malloc(20); //3+1+5+1+8+1+1
				scanf("%s %s", tempUID, tempPW);
				sprintf(msg, "REG %s %s\n", tempUID, tempPW);

				n=sendto(fd, msg, 19, 0, res->ai_addr,res->ai_addrlen);
				if (n==-1) exit(1);

				addrlen=sizeof(addr);

				TimerON(fd);
				n=recvfrom(fd,buffer,BUFFERSIZE,0, (struct sockaddr*) &addr, &addrlen);
				if(n==-1) printf("Timeout reached");
				TimerOFF(fd);

				if (strncmp(buffer, "RRG OK", 6)==0){
					write(1,"User successfully registered\n",29);
				}
				else if (strncmp(buffer, "RRG DUP", 7)==0){
					write(1,"User already exists\n",20);
				}
				else if (strncmp(buffer, "RRG NOK", 7)==0){
					write(1,"User registration failed\n",25);
				}

				free(msg);
				break;

			case 1: // Command: unregister UID pass
				msg=(char*)malloc(20); //3+1+5+1+8+1+1
				scanf("%s %s", tempUID, tempPW);
				sprintf(msg, "UNR %s %s\n", tempUID, tempPW);

				n=sendto(fd, msg, 19, 0, res->ai_addr,res->ai_addrlen);
				if (n==-1) exit(1);

				addrlen=sizeof(addr);

				TimerON(fd);
				n=recvfrom(fd,buffer,BUFFERSIZE,0, (struct sockaddr*) &addr, &addrlen);
				if(n==-1) printf("Timeout reached");
				TimerOFF(fd);

				if (strncmp(buffer, "RUN OK", 6)==0){
					write(1,"User successfully unregistered\n",31);
				}
				else if (strncmp(buffer, "RUN NOK", 7)==0){
					write(1,"User unregistration failed\n",27);
				}
		
				free(msg);
				break;

			case 2: // Command: login UID pass
				msg=(char*)malloc(20); //3+1+5+1+8+1+1
				scanf("%s %s", u.UID, u.PW);
				sprintf(msg, "LOG %s %s\n", u.UID, u.PW);

				n=sendto(fd, msg, 19, 0, res->ai_addr,res->ai_addrlen);
				if (n==-1) exit(1);

				addrlen=sizeof(addr);

				TimerON(fd);
				n=recvfrom(fd,buffer,BUFFERSIZE,0, (struct sockaddr*) &addr, &addrlen);
				if(n==-1) printf("Timeout reached");
				TimerOFF(fd);
				
				if (strncmp(buffer, "RLO NOK", 7)==0){
					strcpy(u.UID, "");
					strcpy(u.PW, "");
					write(1,"UID or password are wrong\n",26);
				}
				else if (strncmp(buffer, "RLO OK", 6)==0){
					write(1,"You are now logged in\n",22);
				}

				free(msg);
				break;

			case 3: // Command: logout
				msg=(char*)malloc(20); //3+1+5+1+8+1+1

				if (strcmp(u.UID, "")==0){
					free(msg); 
					write(1,"You are not logged in\n",22); 
					break;
				}
				sprintf(msg, "OUT %s %s\n", u.UID, u.PW);

				n=sendto(fd, msg, 19, 0, res->ai_addr,res->ai_addrlen);
				if (n==-1) exit(1);

				addrlen=sizeof(addr);

				TimerON(fd);
				n=recvfrom(fd,buffer,BUFFERSIZE,0, (struct sockaddr*) &addr, &addrlen);
				if(n==-1) printf("Timeout reached");
				TimerOFF(fd);

				if (strncmp(buffer, "ROU OK", 6)==0){
					strcpy(u.UID, "");
					strcpy(u.PW, "");
					write(1,"You are now logged out\n",23);
				}
				else if(strncmp(buffer, "ROU NOK", 7)==0){
					write(1,"UID or password are not valid\n",30);
				}

				free(msg);
				break;

			case 4: // Command: showuid
				msg=(char*)malloc(7);

				if (strcmp(u.UID, "")==0){
					free(msg); 
					write(1,"You are not logged in\n",22); 
					break;
				}

				sprintf(msg, "%s\n", u.UID);
				write(1, msg, 6);
				free(msg);
				break;

			case 5: // Command: exit
				ext = 1;
				break;
			
			case 6: // Command: groups
				msg=(char*)malloc(5);
				sprintf(msg, "GLS\n");

				n=sendto(fd, msg, 4, 0, res->ai_addr,res->ai_addrlen);
				if (n==-1) exit(1);

				addrlen=sizeof(addr);

				TimerON(fd);
				n=recvfrom(fd,gmsg, MAXGROUPSMSG-1,0, (struct sockaddr*) &addr, &addrlen);
				if(n==-1) printf("Timeout reached");
				TimerOFF(fd);
				
				bufferCounter=0;
				sscanf(gmsg,"RGL %d%ln",&aux,&n);
				bufferCounter+=n;
				while(aux>0){
					sscanf(gmsg+bufferCounter," %s %s %s%ln",gid,temp,mid,&n);
					bufferCounter+=n;
					printf("%s %s %s\n",gid,temp,mid);
					aux--;
				}
				free(msg);
				break;
			
			case 7: // Command: subscribe GID GName

				scanf("%s %s", gid, temp);

				msg=(char*)malloc(15 + strlen(temp)); //3+1+5+1+2+1+2

				if (strcmp(u.UID, "")==0) {
					free(msg); 
					write(1,"You are not logged in\n",22); 
					break;
				}

				sprintf(msg, "GSR %s %s %s\n", u.UID, gid, temp);

				n=sendto(fd, msg, strlen(msg), 0, res->ai_addr,res->ai_addrlen);
				if (n==-1) exit(1);

				addrlen=sizeof(addr);

				TimerON(fd);
				n=recvfrom(fd,buffer,BUFFERSIZE,0, (struct sockaddr*) &addr, &addrlen);
				if(n==-1) printf("Timeout reached");
				TimerOFF(fd);

				if (strncmp(buffer, "RGS OK", 6)==0){
					printf("Group subscribed: %s - \"%s\"\n",gid,temp);
				}
				else if(strncmp(buffer, "RGS NEW", 7)==0){
					sscanf(buffer,"RGS NEW %s",gid);
					printf("New group created and subscribed: %s - \"%s\"\n",gid,temp);
				}
				else if(strncmp(buffer, "RGS E_USR", 9)==0){
					printf("Invalid UID\n");
				}
				else if(strncmp(buffer, "RGS E_GRP", 9)==0){
					printf("Invalid GID\n");
				}
				else if(strncmp(buffer, "RGS E_GNAME", 11)==0){
					printf("Invalid GNAME\n");
				}
				else if(strncmp(buffer, "RGS E_FULL", 10)==0){
					printf("The groups are maxed out\n");
				}
				else if(strncmp(buffer, "RGS NOK",7)==0){
					printf("Subscribe failed\n");
				}

				free(msg);
				break;

			case 8: // Command: unsubscribe GID
				msg=(char*)malloc(14); //3+1+5+1+2+1+1

				scanf("%s", gid);

				if (strcmp(u.UID, "")==0) {
					free(msg);
					write(1,"You are not logged in\n",22); 
					break;
				}

				sprintf(msg, "GUR %s %s\n", u.UID, gid);

				n=sendto(fd, msg, 13, 0, res->ai_addr,res->ai_addrlen);
				if (n==-1) exit(1);

				addrlen=sizeof(addr);

				TimerON(fd);
				n=recvfrom(fd,buffer,BUFFERSIZE,0, (struct sockaddr*) &addr, &addrlen);
				if(n==-1) printf("Timeout reached");
				TimerOFF(fd);

				if (strncmp(buffer, "RGU OK", 6)==0){
					printf("Group unsubscribed successfully\n");
				}
				else if(strncmp(buffer, "RGU E_USR", 9)==0){
					printf("Invalid UID\n");
				}
				else if(strncmp(buffer, "RGU E_GRP", 9)==0){
					printf("Invalid GID\n");
				}
				else if(strncmp(buffer, "RGU NOK",7)==0){
					printf("Unsubscribe failed\n");
				}

				free(msg);
				break;

			case 9: // Command: my_groups
				msg=(char*)malloc(11); //3+1+5+1+1

				if (strcmp(u.UID, "")==0) {
					free(msg); 
					write(1,"You are not logged in\n",22); 
					break;
				}

				sprintf(msg, "GLM %s\n", u.UID);

				n=sendto(fd, msg, 10, 0, res->ai_addr,res->ai_addrlen);
				if (n==-1) exit(1);

				addrlen=sizeof(addr);

				TimerON(fd);
				n=recvfrom(fd,buffer,BUFFERSIZE,0, (struct sockaddr*) &addr, &addrlen);
				if(n==-1) printf("Timeout reached");
				TimerOFF(fd);

				if(strncmp(buffer, "RGM E_USR", 9)==0){
					printf("Invalid UID\n");
				}
				else if(strncmp(buffer, "RGM 0", 5)==0){
					printf("You have not subscribed to any groups\n");
				}
				else{
					bufferCounter=0;
					sscanf(buffer,"RGM %d%ln",&aux,&n);
					bufferCounter+=n;
					while(aux>0){
						sscanf(buffer+bufferCounter," %s %s %s%ln",gid,temp,mid,&n);
						bufferCounter+=n;
						printf("%s %s %s\n",gid,temp,mid);
						aux--;
					}
				}

				free(msg);
				break;

			case 10: // Command: select GID
				scanf("%s", current_GID);
				printf("Group %s is now the active group\n", current_GID);
				break;

			case 11: // Command: showgid
				msg=(char*)malloc(4);

				if (strcmp(current_GID, "")==0) {
					free(msg); 
					write(1,"You have not selected any group\n",32); 
					break;
				}

				sprintf(msg, "%s\n", current_GID);
				write(1, msg, 4);
				free(msg);
				break;

			case 12: // Command: ulist
				msg=(char*)malloc(8); //3+1+2+1+1

				if (strcmp(current_GID, "")==0) {
					free(msg); 
					write(1,"You have not selected any group\n",32);
					break;
				}

				sprintf(msg, "ULS %s\n", current_GID);

				initTCP();
				
				n=connect(fd2, res2->ai_addr, res2->ai_addrlen);
				
				if(n==-1){
					exit(1);
				}

				n=write(fd2, msg, 7);
				if(n==-1) exit(1);

				n=read(fd2, buffer, BUFFERSIZE);
				if(n==-1) exit(1);

				if(strncmp(buffer, "RUL NOK", 7)==0){
					free(msg);
					printf("Group does not exist\n");
					freeaddrinfo(res2);
					close(fd2);
					break;
				}

				printf("Users subscribed to group %s:\n",current_GID);
				spaces=0;
				aux=0;
				while(n > 0){
					bufferCounter=0;
					while(bufferCounter < n){
						if(buffer[bufferCounter]==' '){
							spaces++;
						}
						else if(spaces >= 3){
							if(buffer[bufferCounter]!='\n'){
								if(aux == 5)
									aux=0;
								while(aux < 5){
									printf("%c",buffer[bufferCounter]);
									bufferCounter++;
									aux++;
									if(bufferCounter >= n){
										break;
									}
								}
							}
	
							if(buffer[bufferCounter] == '\n'){
								printf("\n");
								break;
							}
							printf(" ");
						}
						bufferCounter++;
					}
					bzero(buffer,BUFFERSIZE);
					n=read(fd2, buffer, BUFFERSIZE);
					if(n==-1) exit(1);
				}

				freeaddrinfo(res2);
				close(fd2);
				free(msg);
				break;

			case 13: // Command: post "text" [Fname]
				if (strcmp(current_GID, "")==0 || strcmp(u.UID, "")==0) {
					write(1,"There is no group selected or you are not logged in\n",52); 
					break;
				}
				isInText = 0;
				spaces = 0;
				txt=(char*)malloc(MAXTSIZE);
				fname=(char*)malloc(MAXFNAME);

				bzero(txt,MAXTSIZE);
				bzero(fname,MAXFNAME);

				auxc = getchar();
				while(auxc != '\n'){
					if(auxc == '\"'){
						if (isInText==0) isInText=1;
						else isInText=0;
					}
					if(spaces == 1 && auxc != '\"' && isInText == 1){
						strncat(txt,&auxc,1);
					}
					else if(spaces == 2){
						strncat(fname,&auxc,1);
					}
					if(auxc == ' '){
						if (isInText==0) spaces++;
					}
					auxc = getchar();
				}

				initTCP();

				n=connect(fd2, res2->ai_addr, res2->ai_addrlen);
				if(n==-1){
					exit(1);
				}
				
				if(spaces == 1){//Caso sem ficheiro
					sprintf(temp, "%ld", strlen(txt));
					msg=(char*)malloc(16 + strlen(temp) + strlen(txt)); //3+1+5+1+2+1+?+1+?+2
					sprintf(msg, "PST %s %s %ld %s\n", u.UID, current_GID, strlen(txt), txt);
					n=write(fd2, msg, strlen(msg));
					if(n==-1){
						exit(1);
					}

				}
				else if(spaces == 2){//Caso com ficheiro
					ptr = fopen(fname,"r");
					fseek(ptr,0,SEEK_END);
					fsize = ftell(ptr);
					fseek(ptr, 0, SEEK_SET);

					sprintf(temp, "%ld", strlen(txt));
					msg=(char*)malloc(29 + strlen(temp) + strlen(txt) + strlen(fname)); //3+1+5+1+2+1+?+1+?+1+?+1+?+1+?+2
					sprintf(msg, "PST %s %s %ld %s %s %d ", u.UID, current_GID, strlen(txt), txt, fname, fsize);

					write(fd2,msg,strlen(msg));

					while (fsize > 0){
						bzero(buffer,BUFFERSIZE);
						n=fread(buffer,1,BUFFERSIZE,ptr);
						write(fd2,buffer,BUFFERSIZE);
						fsize = fsize - n;
					}
					
					write(fd2,"\n",2);
					fclose(ptr);
				}

				n=read(fd2, buffer, BUFFERSIZE);
				if(n==-1){ 
					exit(1);
				}

				if(strncmp(buffer, "RPT NOK", 7)==0){
					printf("Failed to post the message\n");
				}
				else{
					sscanf(buffer, "RPT %s",mid);
					printf("Message successfully posted: MID = %s\n",mid);
				}

				freeaddrinfo(res2);
				close(fd2);
				free(msg);
				free(txt);
				free(fname);
				break;

			case 14: // Command: retrieve MID

				scanf("%s", mid);
				
				if (strcmp(current_GID, "")==0 || strcmp(u.UID, "")==0){
					write(1,"There is no group selected or you are not logged in\n",52); 
					break;
				}
				
				msg=(char*)malloc(19); //3+1+5+1+2+1+4+1+1
				
				sprintf(msg, "RTV %s %s %s\n", u.UID, current_GID, mid);
				
				initTCP();

				n=connect(fd2, res2->ai_addr, res2->ai_addrlen);
				if(n==-1) exit(1);

				n=write(fd2, msg, 18);
				if(n==-1) exit(1);

				isFile=0;
				spaces=0;
				fsize=0;
				isInText=0;
				firstexec=1;

				bzero(buffer,BUFFERSIZE);

				n=read(fd2, buffer, 7);
				if(n==-1) exit(1);
			
				
				if(strncmp(buffer, "RRT EOF", 7)==0){
					printf("No messages available\n");
					free(msg);
					break;
				}
				else if(strncmp(buffer,"RRT NOK",7)==0){
					printf("Retrieve failed\n");
					free(msg);
					break;
				}

				fname=(char*)malloc(MAXFNAME);
				fdatasize=(char*)malloc(MAXFDIGITSIZE);
				txt=(char*)malloc(MAXTSIZE);
				tsize=(char*)malloc(4);

				bzero(tsize,4);
				bzero(txt,MAXTSIZE);
				bzero(mid,5);
				bzero(tempUID,UIDSIZE);
				bzero(fname,MAXFNAME);
				bzero(fdatasize,MAXFDIGITSIZE);
				bzero(msg_no,3);

				n=read(fd2, &auxc, 1);
				if(n==-1) exit(1);
				while(auxc != ' '){
					strncat(msg_no,&auxc,1);
					n=read(fd2, &auxc, 1);
					if(n==-1) exit(1);
				}

				spaces++;

				aux = atoi(msg_no);

				printf("%d message(s) retrieved:\n",aux);

				if (stat("./downloads", &st) == -1) {
    				mkdir("./downloads", 0700);
				}

				chdir("./downloads");

				bzero(buffer,BUFFERSIZE);
				n=read(fd2, buffer, BUFFERSIZE);
				if(n==-1) exit(1);
				
				while(n!=0) {
					bufferCounter=0;
					while(bufferCounter <= n){

						if(buffer[bufferCounter] == '/' && isInText==0) isFile=1;
						
						// Adicionar espacos (sem estarem numa msg ou dentro de ficheiro)
						if(isInText==0 && spaces<8){
							if(buffer[bufferCounter] == ' '){
								spaces++;
								if(spaces == 4){
									size=atoi(tsize);
									if(size > 0)
										isInText = 1;
								}
								bufferCounter++;
								continue;
							}
						}

						if(spaces == 1){
							strncat(mid,&buffer[bufferCounter],1);
						}
						if(spaces == 2){
							strncat(tempUID,&buffer[bufferCounter],1);
						}
						if(spaces == 3){
							strncat(tsize,&buffer[bufferCounter],1);
						}
						if(spaces == 4){	//Mensagem (texto)
							if(isInText == 1){
								if(size>0){
									strncat(txt,&buffer[bufferCounter],1);
									size--;
								}
								if(size==0) isInText = 0;
							}
						}

						if(spaces == 5 && isFile==0){	//Sem Ficheiro
							printf("%s - \"%s\";\n",mid,txt);

							spaces=1;
							bufferCounter--;

							bzero(tsize,4);
							bzero(txt,MAXTSIZE);
							bzero(mid,5);
							bzero(tempUID,UIDSIZE);
							bzero(fname,MAXFNAME);
							bzero(fdatasize,MAXFDIGITSIZE);
						}
						
						//Se houver ficheiro
						if(spaces == 6)
							strncat(fname,&buffer[bufferCounter],1);
						if(spaces == 7)
							strncat(fdatasize,&buffer[bufferCounter],1);
						if(spaces == 8){
							if(bufferCounter>=n) break; //Se o buffer terminar no espaco 8

							if(firstexec == 1){
								ptr = fopen(fname, "w");
								firstexec = 0;
							}
							else
								ptr = fopen(fname, "a");

							if(fsize == 0)
								fsize = atoi(fdatasize);

							while(fsize > 0) {
								fputc(buffer[bufferCounter++], ptr);

								fsize--;
								if(bufferCounter == n){
									break;
								}
							}

							if(fsize==0){
								printf("%s - \"%s\"; file stored: %s\n",mid,txt,fname);

								bufferCounter--;
								isFile=0;
								spaces=0;
								firstexec = 1;

								bzero(tsize,4);
								bzero(txt,MAXTSIZE);
								bzero(mid,5);
								bzero(tempUID,UIDSIZE);
								bzero(fname,MAXFNAME);
								bzero(fdatasize,MAXFDIGITSIZE);
							}
							fclose(ptr);	
						}
						bufferCounter++;
					}
					bzero(buffer,BUFFERSIZE);
					n=read(fd2, buffer, BUFFERSIZE);
					if(n==-1) exit(1);
				}

				if(spaces == 4) {
					printf("%s - \"%s\";\n",mid,txt);
					bzero(tsize,4);
					bzero(txt,MAXTSIZE);
					bzero(mid,5);
					bzero(tempUID,UIDSIZE);
					bzero(fname,MAXFNAME);
					bzero(fdatasize,MAXFDIGITSIZE);
				}

				chdir("..");

				freeaddrinfo(res2);
				close(fd2);
				free(msg);
				free(fname);
				free(txt);
				free(fdatasize);
				free(tsize);
				break;
		}
		if(ext) break;
	}
	freeaddrinfo(res);
	close(fd);
	return 0;
}



User processInput(int argc, char** argv)
{
	User u;

	if (argc!=1 && argc!=3 && argc!=5){
		exit(EXIT_FAILURE);
	}


	if (argc >= 3){
		if (strcmp(argv[1], "-n") == 0){
			strcpy(u.DSIP, argv[2]);
			if (argc==5){
				strcpy(u.DSPort, argv[4]);
			}
		}
		if (strcmp(argv[1], "-p") == 0){
			strcpy(u.DSPort, argv[2]);
			if (argc==5){
				strcpy(u.DSIP, argv[4]);
			}
		}
	}
	else{
		strcpy(u.DSPort,PORT);

		char hostbuffer[256];
		char *IPbuffer;
		struct hostent *host_entry;
	
		gethostname(hostbuffer, sizeof(hostbuffer));
	
		host_entry = gethostbyname(hostbuffer);
	
		IPbuffer = inet_ntoa(*((struct in_addr*)host_entry->h_addr_list[0]));
		strcpy(u.DSIP,IPbuffer);
	}

	return u;
}


void initUDP(){
	fd=socket(AF_INET,SOCK_DGRAM, 0);
	if (fd==-1) exit(1);

	memset(&hints,0,sizeof hints);
	hints.ai_family=AF_INET;
	hints.ai_socktype=SOCK_DGRAM;

	errcode=getaddrinfo(u.DSIP, u.DSPort, &hints, &res);
	if(errcode!=0) exit(1);

	return;
}


void initTCP(){
	fd2=socket(AF_INET,SOCK_STREAM, 0);
	if (fd2==-1) exit(1);

	memset(&hints2,0,sizeof hints2);
	hints2.ai_family=AF_INET;
	hints2.ai_socktype=SOCK_STREAM;

	errcode=getaddrinfo(u.DSIP, u.DSPort, &hints2, &res2);
	if(errcode!=0) exit(1);
	
	return;
}

int TimerON(int sd){
	struct timeval tmout;
	memset((char *)&tmout,0,sizeof(tmout)); /* clear time structure */
	tmout.tv_sec=15; /* Wait for 15 sec for a reply from server. */

	return(setsockopt(sd, SOL_SOCKET, SO_RCVTIMEO, (struct timeval *)&tmout,sizeof(struct timeval)));
}

int TimerOFF(int sd)
{
	struct timeval tmout;
	memset((char *)&tmout,0,sizeof(tmout)); /* clear time structure */

	return(setsockopt(sd, SOL_SOCKET, SO_RCVTIMEO, (struct timeval *)&tmout,sizeof(struct timeval)));
}

int getCommand(char* cmd)
{
	if (strcmp(cmd, "reg")==0){
		return 0;
	}
	if (strcmp(cmd, "unr")==0 || strcmp(cmd, "unregister")==0){
		return 1;
	}
	if (strcmp(cmd, "login")==0){
		return 2;
	}
	if (strcmp(cmd, "logout")==0){
		return 3;
	}
	if (strcmp(cmd, "showuid")==0 || strcmp(cmd, "su")==0){
		return 4;
	}
	if (strcmp(cmd, "exit")==0){
		return 5;
	}
	if (strcmp(cmd, "groups")==0 || strcmp(cmd, "gl")==0){
		return 6;
	}
	if (strcmp(cmd, "subscribe")==0 || strcmp(cmd, "s")==0){
		return 7;
	}
	if (strcmp(cmd, "unsubscribe")==0 || strcmp(cmd, "u")==0){
		return 8;
	}
	if (strcmp(cmd, "my_groups")==0 || strcmp(cmd, "mgl")==0){
		return 9;
	}
	if (strcmp(cmd, "select")==0 || strcmp(cmd, "sag")==0){
		return 10;
	}
	if (strcmp(cmd, "showgid")==0 || strcmp(cmd, "sg")==0){
		return 11;
	}
	if (strcmp(cmd, "ulist")==0 || strcmp(cmd, "ul")==0){
		return 12;
	}
	if (strcmp(cmd, "post")==0){
		return 13;
	}
	if (strcmp(cmd, "retrieve")==0 || strcmp(cmd, "r")==0){
		return 14;
	}

	return -1;
}