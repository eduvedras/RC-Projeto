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
#include <dirent.h>
#include <errno.h>
#include "DS.h"


int main(int argc,char** argv){	
	char name_cmd[MAXCMD];
	int cmd,aux;
	char tempUID[UIDSIZE],tempPW[MAXPW];
	char tempGID[GIDSIZE],tempGNAME[MAXGNAME];
	char tempMID[MIDSIZE];
	char auxmsg[34];
	char text[MAXTSIZE],tsize[4];
	int lastgid;
	struct stat st = {0};
	GROUPLIST *list;
	Server s;

    s = processInput(argc,argv);

	if (stat("./USERS", &st) == -1) {
    	mkdir("./USERS", 0700);
	}

	if (stat("./GROUPS", &st) == -1) {
    	mkdir("./GROUPS", 0700);
	}

	list = (GROUPLIST*)malloc(sizeof(GROUPLIST)*100);
	lastgid=ListGroupsDir(list);
	free(list);
	
	if(fork()>0){//UDP commands
		int fd, errcode;
		ssize_t n;
		socklen_t addrlen;
		struct addrinfo hints,*res;
		struct sockaddr_in addr;
		char buffer[BUFFERSIZE];
		char groupsbuffer[MAXGROUPSMSG];
		char auxbuffer[MAXGROUPSMSG];
		int n_groups;
		int i;

		//iniciar UDP

		fd=socket(AF_INET,SOCK_DGRAM, 0);
		if (fd==-1) exit(1);

		memset(&hints,0,sizeof hints);
		hints.ai_family=AF_INET;
		hints.ai_socktype=SOCK_DGRAM;
		hints.ai_flags=AI_PASSIVE;

		errcode=getaddrinfo(NULL, s.DSport, &hints, &res);
		if(errcode!=0) exit(1);

		n=bind(fd, res->ai_addr, res->ai_addrlen);
		if(n==-1) exit(1);

		while(1){
			addrlen=sizeof(addr);
			bzero(buffer,BUFFERSIZE);
			n=recvfrom(fd,buffer,BUFFERSIZE,0, (struct sockaddr*) &addr, &addrlen);
			if(n==-1) exit(1);

			sscanf(buffer,"%s",name_cmd);
			cmd = getCommand(name_cmd);

			switch(cmd){
				case -1://Erro
					sprintf(buffer,"ERR\n");

					TimerON(fd);
					n=sendto(fd, buffer, strlen(buffer), 0, (struct sockaddr*) &addr,addrlen);
					if (n==-1) printf("Timeout reached");
					TimerOFF(fd);

					if(s.v == 1)
						printf("Message sent:{%s}\nError\n",buffer);
					if (n==-1) exit(1);
					break;

				case 0://reg UID PW
					sscanf(buffer,"REG %s %s", tempUID,tempPW);
	
					bzero(buffer,BUFFERSIZE);
					if(strlen(tempUID)!= 5 || strlen(tempPW) != 8){
						sprintf(buffer,"RRG NOK\n");

						TimerON(fd);
						n=sendto(fd, buffer, strlen(buffer), 0, (struct sockaddr*) &addr,addrlen);
						if (n==-1) printf("Timeout reached");
						TimerOFF(fd);

						if(s.v == 1)
							printf("Message sent:{%s}\n%s or %s:UID or PW invalid\n",buffer,tempUID,tempPW);
						break;
					}
					n=CreateUserDir(tempUID,tempPW);
					if(n==0){
						sprintf(buffer,"RRG NOK\n");

						TimerON(fd);
						n=sendto(fd, buffer, strlen(buffer), 0, (struct sockaddr*) &addr,addrlen);
						if (n==-1) printf("Timeout reached");
						TimerOFF(fd);

						if(s.v == 1)
							printf("Message sent:{%s}\nError creating user dir\n",buffer);
						break;
					}

					if(n==2){
						sprintf(buffer,"RRG DUP\n");

						TimerON(fd);
						n=sendto(fd, buffer, strlen(buffer), 0, (struct sockaddr*) &addr,addrlen);
						if (n==-1) printf("Timeout reached");
						TimerOFF(fd);

						if(s.v == 1)
							printf("Message sent:{%s}\nUser already exists\n",buffer);
						break;
					}

					sprintf(buffer,"RRG OK\n");

					TimerON(fd);
					n=sendto(fd, buffer, strlen(buffer), 0, (struct sockaddr*) &addr,addrlen);
					if (n==-1) printf("Timeout reached");
					TimerOFF(fd);

					if(s.v == 1)
						printf("Message sent:{%s}\n%s: User created with password %s\n",buffer,tempUID,tempPW);
					break;

				case 1://unr UID PW
					sscanf(buffer,"UNR %s %s",tempUID,tempPW);

					bzero(buffer,BUFFERSIZE);
					if(strlen(tempUID)!= 5 || strlen(tempPW) != 8){
						sprintf(buffer,"RUN NOK\n");

						TimerON(fd);
						n=sendto(fd, buffer, strlen(buffer), 0, (struct sockaddr*) &addr,addrlen);
						if (n==-1) printf("Timeout reached");
						TimerOFF(fd);

						if(s.v == 1)
							printf("Message sent:{%s}\n%s or %s:UID or PW invalid\n",buffer,tempUID,tempPW);
						break;
					}
					n=DelUserDir(tempUID,tempPW);
					if(n==0){
						sprintf(buffer,"RUN NOK\n");

						TimerON(fd);
						n=sendto(fd, buffer, strlen(buffer), 0, (struct sockaddr*) &addr,addrlen);
						if (n==-1) printf("Timeout reached");
						TimerOFF(fd);

						if(s.v == 1)
							printf("Message sent:{%s}\nError deleting user dir\n",buffer);
						break;
					}
					sprintf(buffer,"RUN OK\n");

					TimerON(fd);
					n=sendto(fd, buffer, strlen(buffer), 0, (struct sockaddr*) &addr,addrlen);
					if (n==-1) printf("Timeout reached");
					TimerOFF(fd);

					if(s.v == 1)
						printf("Message sent:{%s}\n%s: User deleted\n",buffer,tempUID);
					break;

				case 2://login UID PW
					sscanf(buffer,"LOG %s %s",tempUID,tempPW);

					bzero(buffer,BUFFERSIZE);
					if(strlen(tempUID)!= 5 || strlen(tempPW) != 8){
						sprintf(buffer,"RLO NOK\n");

						TimerON(fd);
						n=sendto(fd, buffer, strlen(buffer), 0, (struct sockaddr*) &addr,addrlen);
						if (n==-1) printf("Timeout reached");
						TimerOFF(fd);

						if(s.v == 1)
							printf("Message sent:{%s}\n%s or %s:UID or PW invalid\n",buffer,tempUID,tempPW);
						break;
					}
					n=Login(tempUID,tempPW);
					if(n==0){
						sprintf(buffer,"RLO NOK\n");

						TimerON(fd);
						n=sendto(fd, buffer, strlen(buffer), 0, (struct sockaddr*) &addr,addrlen);
						if (n==-1) printf("Timeout reached");
						TimerOFF(fd);

						if(s.v == 1)
							printf("Message sent:{%s}\nError logging in\n",buffer);
						break;
					}
					sprintf(buffer,"RLO OK\n");

					TimerON(fd);
					n=sendto(fd, buffer, strlen(buffer), 0, (struct sockaddr*) &addr,addrlen);
					if (n==-1) printf("Timeout reached");
					TimerOFF(fd);

					if(s.v == 1)
						printf("Message sent:{%s}\n%s:User logged in with password %s\n",buffer,tempUID,tempPW);
					break;

				case 3://logout UID PW
					sscanf(buffer,"OUT %s %s",tempUID,tempPW);

					bzero(buffer,BUFFERSIZE);
					if(strlen(tempUID)!= 5 || strlen(tempPW) != 8){
						sprintf(buffer,"ROU NOK\n");

						TimerON(fd);
						n=sendto(fd, buffer, strlen(buffer), 0, (struct sockaddr*) &addr,addrlen);
						if (n==-1) printf("Timeout reached");
						TimerOFF(fd);

						if(s.v == 1)
							printf("Message sent:{%s}\n%s or %s:UID or PW invalid\n",buffer,tempUID,tempPW);
						break;
					}
					n=DelFile(tempUID,tempPW,"login");
					if(n==0){
						sprintf(buffer,"ROU NOK\n");

						TimerON(fd);
						n=sendto(fd, buffer, strlen(buffer), 0, (struct sockaddr*) &addr,addrlen);
						if (n==-1) printf("Timeout reached");
						TimerOFF(fd);

						if(s.v == 1)
							printf("Message sent:{%s}\nError deleting login file\n",buffer);
						break;
					}
					sprintf(buffer,"ROU OK\n");

					TimerON(fd);
					n=sendto(fd, buffer, strlen(buffer), 0, (struct sockaddr*) &addr,addrlen);
					if (n==-1) printf("Timeout reached");
					TimerOFF(fd);

					if(s.v == 1)
							printf("Message sent:{%s}\n%s:User logged out\n",buffer,tempUID);
					break;

				case 4://groups
					bzero(groupsbuffer,MAXGROUPSMSG);
					bzero(auxmsg,34);
					list = (GROUPLIST*)malloc(sizeof(GROUPLIST)*100);
					
					n=ListGroupsDir(list);

					i=0;
	
					sprintf(groupsbuffer,"RGL %d",list->no_groups);
					while(i < n){
						sprintf(auxmsg," %s %s %s",list->group_no[i],list->group_name[i],list->mid[i]);
						strcat(groupsbuffer,auxmsg);
						i++;
					}

					strcat(groupsbuffer,"\n");

					TimerON(fd);
					n=sendto(fd, groupsbuffer, strlen(groupsbuffer), 0, (struct sockaddr*) &addr,addrlen);
					if (n==-1) printf("Timeout reached");
					TimerOFF(fd);

					free(list);
					if(s.v == 1)
							printf("Message sent:{%s}\nGroups shown\n",buffer);
					break;

				case 5://subscribe GID GNAME
					sscanf(buffer,"GSR %s %s %s",tempUID,tempGID,tempGNAME);
					bzero(buffer,BUFFERSIZE);

					if(strlen(tempUID)!=5){
						sprintf(buffer,"RGS E_USR\n");

						TimerON(fd);
						n=sendto(fd, buffer, strlen(buffer), 0, (struct sockaddr*) &addr,addrlen);
						if (n==-1) printf("Timeout reached");
						TimerOFF(fd);

						if(s.v == 1)
							printf("Message sent:{%s}\n%s:UID invalid\n",buffer,tempUID);
						break;
					}

					if(strlen(tempGNAME)>24){
						sprintf(buffer,"RGS E_GNAME\n");

						TimerON(fd);
						n=sendto(fd, buffer, strlen(buffer), 0, (struct sockaddr*) &addr,addrlen);
						if (n==-1) printf("Timeout reached");
						TimerOFF(fd);

						if(s.v == 1)
							printf("Message sent:{%s}\n%s:Gname is invalid\n",buffer,tempGNAME);
						break;
					}

					list = (GROUPLIST*)malloc(sizeof(GROUPLIST)*100);
					lastgid=ListGroupsDir(list);
					
					if(atoi(tempGID) > lastgid || strlen(tempGID)!=2){
						sprintf(buffer,"RGS E_GRP\n");

						TimerON(fd);
						n=sendto(fd, buffer, strlen(buffer), 0, (struct sockaddr*) &addr,addrlen);
						if (n==-1) printf("Timeout reached");
						TimerOFF(fd);

						if(s.v == 1)
							printf("Message sent:{%s}\n%s:Gid is invalid\n",buffer,tempGID);
						break;
					}

					n=ListUsersDir(tempUID);
					if(n==0){
						sprintf(buffer,"RGS E_USR\n");

						TimerON(fd);
						n=sendto(fd, buffer, strlen(buffer), 0, (struct sockaddr*) &addr,addrlen);
						if (n==-1) printf("Timeout reached");
						TimerOFF(fd);

						if(s.v == 1)
							printf("Message sent:{%s}\n%s:User is not logged in\n",buffer,tempUID);
						break;
					}	
					
					if(strcmp(tempGID,"00")==0){
						aux=0;
						while(aux < lastgid){
							if(strcmp(tempGNAME,list->group_name[aux])==0){
								sprintf(buffer,"RGS E_GNAME\n");

								TimerON(fd);
								n=sendto(fd, buffer, strlen(buffer), 0, (struct sockaddr*) &addr,addrlen);
								if (n==-1) printf("Timeout reached");
								TimerOFF(fd);

								if(s.v == 1)
									printf("Message sent:{%s}\n%s:Gname already exists\n",buffer,tempGNAME);
								break;
							}
							aux++;
						}
						free(list);
						if(aux != lastgid){
							break;
						}
						
						n=creategroup(tempUID,tempGNAME);

						if(n==0){
							sprintf(buffer,"RGS E_FULL\n");

							TimerON(fd);
							n=sendto(fd, buffer, strlen(buffer), 0, (struct sockaddr*) &addr,addrlen);
							if (n==-1) printf("Timeout reached");
							TimerOFF(fd);

							if(s.v == 1)
								printf("Message sent:{%s}\nGroup limit has been reached\n",buffer);
							break;
						}

						list = (GROUPLIST*)malloc(sizeof(GROUPLIST)*100);
						lastgid=ListGroupsDir(list);
						free(list);

						if(lastgid > 9){
							sprintf(tempGID,"%d",lastgid);
						}
						else{
							sprintf(tempGID,"0%d",lastgid);
						}

						CreateGroupUser(tempUID,tempGID);//Subscribe user
						
						
						sprintf(buffer,"RGS NEW %s\n",tempGID);

						TimerON(fd);
						n=sendto(fd, buffer, strlen(buffer), 0, (struct sockaddr*) &addr,addrlen);
						if (n==-1) printf("Timeout reached");
						TimerOFF(fd);

						if(s.v == 1)
							printf("Message sent:{%s}\n%s:Group created and subscribed by %s\n",buffer,tempGID,tempUID);
					}
					else{
						free(list);
						CreateGroupUser(tempUID,tempGID);//Subscribe user
						sprintf(buffer,"RGS OK\n");

						TimerON(fd);
						n=sendto(fd, buffer, strlen(buffer), 0, (struct sockaddr*) &addr,addrlen);
						if (n==-1) printf("Timeout reached");
						TimerOFF(fd);

						if(s.v == 1)
							printf("Message sent:{%s}\n%s:Group subscribed by %s\n",buffer,tempGID,tempUID);
					}
					break;

				case 6://unsubscribe GID
					sscanf(buffer,"GUR %s %s",tempUID,tempGID);
					bzero(buffer,BUFFERSIZE);

					if(strlen(tempUID)!=5){
						sprintf(buffer,"RGU E_USR\n");

						TimerON(fd);
						n=sendto(fd, buffer, strlen(buffer), 0, (struct sockaddr*) &addr,addrlen);
						if (n==-1) printf("Timeout reached");
						TimerOFF(fd);

						if(s.v == 1)
							printf("Message sent:{%s}\n%s:User invalid\n",buffer,tempUID);
						break;
					}

					list = (GROUPLIST*)malloc(sizeof(GROUPLIST)*100);
					lastgid=ListGroupsDir(list);
					free(list);

					if(atoi(tempGID) > lastgid || strlen(tempGID)!=2){
						sprintf(buffer,"RGU E_GRP\n");

						TimerON(fd);
						n=sendto(fd, buffer, strlen(buffer), 0, (struct sockaddr*) &addr,addrlen);
						if (n==-1) printf("Timeout reached");
						TimerOFF(fd);

						if(s.v == 1)
							printf("Message sent:{%s}\n%s:Invalid gid\n",buffer,tempGID);
						break;
					}

					n=checkGroupUser(tempUID,tempGID);
					if(n==0){
						sprintf(buffer,"RGU E_USR\n");

						TimerON(fd);
						n=sendto(fd, buffer, strlen(buffer), 0, (struct sockaddr*) &addr,addrlen);
						if (n==-1) printf("Timeout reached");
						TimerOFF(fd);

						if(s.v == 1)
							printf("Message sent:{%s}\n%s:User is not subscribed\n",buffer,tempUID);
						break;
					}

					UnsubscribeGroupUser(tempUID,tempGID);
					sprintf(buffer,"RGU OK\n");

					TimerON(fd);
					n=sendto(fd, buffer, strlen(buffer), 0, (struct sockaddr*) &addr,addrlen);
					if (n==-1) printf("Timeout reached");
					TimerOFF(fd);

					if(s.v == 1)
							printf("Message sent:{%s}\n%s:Group unsubscribed by %s\n",buffer,tempGID,tempUID);
					break;

				case 7://my_groups
					sscanf(buffer,"GLM %s",tempUID);
					bzero(groupsbuffer,MAXGROUPSMSG);
					bzero(buffer,BUFFERSIZE);
					bzero(auxmsg,34);
					bzero(auxbuffer, MAXGROUPSMSG);

					n_groups=0;

					if(strlen(tempUID)!=5){
						sprintf(buffer,"RGU E_USR\n");
						
						TimerON(fd);
						n=sendto(fd, buffer, strlen(buffer), 0, (struct sockaddr*) &addr,addrlen);
						if (n==-1) printf("Timeout reached");
						TimerOFF(fd);

						if(s.v == 1)
							printf("Message sent:{%s}\n%s:Invalid user\n",groupsbuffer,tempUID);
						break;
					}

					n=ListUsersDir(tempUID);
					if(n==0){
						sprintf(buffer,"RGU E_USR\n");

						TimerON(fd);
						n=sendto(fd, buffer, strlen(buffer), 0, (struct sockaddr*) &addr,addrlen);
						if (n==-1) printf("Timeout reached");
						TimerOFF(fd);

						if(s.v == 1)
							printf("Message sent:{%s}\n%s:User is not logged in\n",groupsbuffer,tempUID);
						break;
					}

					list = (GROUPLIST*)malloc(sizeof(GROUPLIST)*100);

					n=ListGroupsDir(list);

					if(n==0){
						sprintf(groupsbuffer,"RGM 0\n");
						
						TimerON(fd);
						n=sendto(fd, groupsbuffer, strlen(groupsbuffer), 0, (struct sockaddr*) &addr,addrlen);
						if (n==-1) printf("Timeout reached");
						TimerOFF(fd);

						if(s.v == 1)
							printf("Message sent:{%s}\n%s:User has not subscribed to any group\n",groupsbuffer,tempUID);
						break;
					}

					aux=0;
					while(aux < n){//Ver quais os grupos que o user esta subscrito
						if(checkGroupUser(tempUID,list->group_no[aux])==1){
							sprintf(auxmsg," %s %s %s",list->group_no[aux],list->group_name[aux],list->mid[aux]);
							strcat(auxbuffer,auxmsg);
							n_groups++;
						}
						aux++;
					}
					free(list);

					sprintf(groupsbuffer,"RGM %d",n_groups);
					strcat(groupsbuffer,auxbuffer);
					strcat(groupsbuffer,"\n");
					
					TimerON(fd);
					n=sendto(fd, groupsbuffer, strlen(groupsbuffer), 0, (struct sockaddr*) &addr,addrlen);
					if (n==-1) printf("Timeout reached");
					TimerOFF(fd);

					if(s.v == 1)
						printf("Message sent:{%s}\n%s:Shown subscribed groups\n",groupsbuffer,tempUID);
					break;

			}
		}
		freeaddrinfo(res);
		close(fd);
	}
	else{//TCP commands ainda há um bug

		DIR *d,*auxd;
		struct dirent *dir,*auxdir;
		int i=0;
		int msg;
		int buffercounter;
		FILE *fp;
		char GROUPpath[12];
		char GROUPnamepath[24];
		char path[50];
		char groupname[MAXGNAME];
		char user[6];
		char fname[MAXFNAME];
		char fsize[MAXFDIGITSIZE];
		int filesize;
		char mid[MIDSIZE];
		char c;
		int msg_no;
		int textsize;
		char author[UIDSIZE];
		int fd, errcode,newfd;
		ssize_t n;
		socklen_t addrlen;
		struct addrinfo hints,*res;
		struct sockaddr_in addr;
		char buffer[BUFFERSIZE];
		int errno;
		int yes = 1;
		

		//initTCP();
		fd=socket(AF_INET,SOCK_STREAM, 0);
		if (fd==-1) exit(1);

		memset(&hints,0,sizeof hints);
		hints.ai_family=AF_INET;
		hints.ai_socktype=SOCK_STREAM;
		hints.ai_flags=AI_PASSIVE;

		errcode=getaddrinfo(NULL, s.DSport, &hints, &res);
		if(errcode!=0) exit(1);

		if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR,
								(void*)&yes, sizeof(yes)) < 0) {
			fprintf(stderr, "setsockopt() failed. Error: %d\n", errno);
		}
		n=bind(fd, res->ai_addr, res->ai_addrlen);
		if(n==-1) {
			exit(1);
		}
	
		if(listen(fd, 5)==-1) exit(1);
		
		while(1){
			addrlen=sizeof(addr);

			newfd=accept(fd, (struct sockaddr*) &addr, &addrlen);
			if(newfd==-1) exit(1);

			bzero(buffer,BUFFERSIZE);
			n=read(newfd,buffer,4);
			if(n==-1) exit(1);

			bzero(name_cmd, MAXCMD);
			sscanf(buffer,"%s",name_cmd);
			cmd = getCommand(name_cmd);

			n=read(newfd,buffer,BUFFERSIZE);
			if(n==-1) exit(1);

			switch(cmd){
				case 8://ulist GID
					bzero(tempGID, GIDSIZE);
					sscanf(buffer,"%s",tempGID);
					bzero(buffer,BUFFERSIZE);

					list = (GROUPLIST*)malloc(sizeof(GROUPLIST)*100);
					lastgid=ListGroupsDir(list);
					free(list);

					if(atoi(tempGID) > lastgid || strlen(tempGID)!=2){
						sprintf(buffer,"RUL NOK\n");
						n=write(newfd,buffer,strlen(buffer));
						if(s.v == 1)
							printf("Message sent:{%s}\n%s:Invalid GID\n",buffer,tempGID);
						if(n==-1) exit(1);
						close(newfd);
						break;
					}

					bzero(GROUPpath,12);
					bzero(GROUPnamepath,24);
					bzero(groupname,MAXGNAME);
					bzero(user,6);

					sprintf(GROUPpath,"./GROUPS/%s",tempGID);
					if(s.v == 1)
							printf("Message sent:{");
					sprintf(buffer,"RUL OK ");
					n=write(newfd,buffer,strlen(buffer));
					if(s.v == 1)
						printf("%s",buffer);
					bzero(buffer,BUFFERSIZE);

					sprintf(GROUPnamepath,"%s/%s_name.txt",GROUPpath,tempGID);	

					fp = fopen(GROUPnamepath,"r");
					n=fread(groupname,MAXGNAME,1,fp);
					fclose(fp);
					
					sprintf(buffer,"%s",groupname);
					n=write(newfd,buffer,strlen(buffer));
					if(s.v == 1)
						printf("%s",buffer);
					bzero(buffer,BUFFERSIZE);

					d = opendir(GROUPpath);
					if (d){
						//Enviar todos os user subscritos neste grupo
						while ((dir = readdir(d)) != NULL){
							if(dir->d_name[0]=='.')
								continue;
							if(dir->d_type == DT_REG){
								if(strlen(dir->d_name)> 9){
									continue;
								}
								
								sprintf(user,"%.5s",dir->d_name);
								sprintf(buffer," %s",user);
								n=write(newfd,buffer,strlen(buffer));
								if(s.v == 1)
									printf("%s",buffer);
								bzero(buffer,BUFFERSIZE);
							}
						}
						
						n=write(newfd,"\n",1);
						if(s.v == 1)
							printf("\n}\n%s:Shown users subscribed to this group\n",tempGID);
						bzero(buffer,BUFFERSIZE);
						closedir(d);
					}
					else
						return -1;
					
					close(newfd);
					break;	

				case 9://post
					aux=0;
					buffercounter=0;
					bzero(fname,MAXFNAME);
					bzero(fsize,MAXFDIGITSIZE);
					bzero(tsize,4);
					bzero(text,MAXTSIZE);
					bzero(tempGID, GIDSIZE);
					bzero(tempUID, UIDSIZE);

					sscanf(buffer,"%s %s %s %n",tempUID,tempGID,tsize,&aux);
					buffercounter+=aux;

					textsize = atoi(tsize);
					if(textsize == 0)
						buffercounter--;
					//O texto pode ter espacos
					while(textsize > 0){
						strncat(text,&buffer[buffercounter],1);
						buffercounter++;
						textsize--;
					}

					list = (GROUPLIST*)malloc(sizeof(GROUPLIST)*100);
					lastgid=ListGroupsDir(list);
					free(list);

					if(strlen(tempUID)!=5 || atoi(tempGID) > lastgid){
						sprintf(buffer,"RPT NOK\n");
						i=write(newfd,buffer,strlen(buffer));
						if(i==-1) exit(1);
						if(s.v == 1)
							printf("Message sent{%s}\n%s or %s:Invalid UID or GID\n",buffer,tempUID,tempGID);
						close(newfd);
						break;
					}
					
					i=ListUsersDir(tempUID);
					if(i==0){
						sprintf(buffer,"RPT NOK\n");
						i=write(newfd,buffer,strlen(buffer));
						if(i==-1) exit(1);
						if(s.v == 1)
							printf("Message sent{%s}\n%s:User is not logged in\n",buffer,tempUID);
						close(newfd);
						break;
					}
					
					i=checkGroupUser(tempUID,tempGID);
					if(i==0){
						sprintf(buffer,"RPT NOK\n");
						i=write(newfd,buffer,strlen(buffer));
						if(i==-1) exit(1);
						if(s.v == 1)
							printf("Message sent{%s}\n%s:User is not subscribed\n",buffer,tempUID);
						close(newfd);
						break;
					}

					list = (GROUPLIST*)malloc(sizeof(GROUPLIST)*100);
					i=ListGroupsDir(list);
					aux=0;
					//Ver qual o mid mais recente deste grupo
					while(aux<i){
						if(strcmp(list->group_no[aux],tempGID)==0){
							strcpy(mid,list->mid[aux]);
						}
						aux++;
					}
					free(list);
					msg=atoi(mid);
					msg++;
					sprintf(mid,"%d",msg);
					if(strlen(mid)==1){
						sprintf(mid,"000%d",msg);
					}
					else if(strlen(mid)==2){
						sprintf(mid,"00%d",msg);
					}
					else if(strlen(mid)==3){
						sprintf(mid,"0%d",msg);
					}

					sprintf(path,"./GROUPS/%s/MSG/%s",tempGID,mid);
					mkdir(path,0700);//criar pasta da nova mensagem

					//Criar ficheiro do autor
					bzero(path,50);
					sprintf(path,"./GROUPS/%s/MSG/%s/A U T H O R.txt",tempGID,mid);
					fp = fopen(path,"w");
					fwrite(tempUID,1,strlen(tempUID),fp);
					fclose(fp);

					//Criar ficheiro com o texto da mensagem
					bzero(path,50);
					sprintf(path,"./GROUPS/%s/MSG/%s/T E X T.txt",tempGID,mid);
					fp = fopen(path,"w");
					fwrite(text,1,strlen(text),fp);
					fclose(fp);
					if(buffer[buffercounter]!='\n' && buffer[buffercounter]!='\0'){//Caso em que ha ficheiro
						sscanf(buffer+buffercounter," %s %s %n",fname,fsize,&aux);
						buffercounter+=aux;

						bzero(path,50);
						sprintf(path,"./GROUPS/%s/MSG/%s/%s",tempGID,mid,fname);
						fp = fopen(path,"w");
						i = atoi(fsize);
						
						while(i>0){
							if(buffercounter==n){
								buffercounter=0;
								n=read(newfd,buffer,BUFFERSIZE);
							}
							if(n!=0){
								fputc(buffer[buffercounter],fp);
								buffercounter++;
								i--;
							}
						}
						fclose(fp);
					}
					bzero(buffer,BUFFERSIZE);
					sprintf(buffer,"RPT %s\n",mid);
					
					i=write(newfd,buffer,strlen(buffer));
					if(i==-1) exit(1);

					if(s.v == 1){
						printf("Message sent{%s}\n%s on %s:User posted on group message:\"%s\"",buffer,tempUID,tempGID,text);
						if(strcmp(fname,"")!=0){
							printf(" %s",fname);
						}
						printf("\n");
					}
					bzero(buffer,BUFFERSIZE);
					close(newfd);
					break;

				case 10://retrieve
					bzero(tempGID, GIDSIZE);
					bzero(tempUID, UIDSIZE);
					bzero(tempMID, MIDSIZE);
					sscanf(buffer,"%s %s %s",tempUID,tempGID,tempMID);
					bzero(buffer,BUFFERSIZE);

					list = (GROUPLIST*)malloc(sizeof(GROUPLIST)*100);
					lastgid=ListGroupsDir(list);
					free(list);

					if(strlen(tempUID)!=5 || atoi(tempGID) > lastgid){
						sprintf(buffer,"RRT NOK\n");
						i=write(newfd,buffer,strlen(buffer));
						if(i==-1) exit(1);
						if(s.v == 1)
							printf("Message sent{%s}\n%s or %s:Invalid UID or GID\n",buffer,tempUID,tempGID);
						close(newfd);
						break;
					}
					
					i=ListUsersDir(tempUID);
					if(i==0){
						sprintf(buffer,"RRT NOK\n");
						i=write(newfd,buffer,strlen(buffer));
						if(i==-1) exit(1);
						if(s.v == 1)
							printf("Message sent{%s}\n%s:User is not logged in\n",buffer,tempUID);
						close(newfd);
						break;
					}
					
					i=checkGroupUser(tempUID,tempGID);
					if(i==0 || strcmp(tempMID,"0000")==0 || strlen(tempMID)!=4){
						sprintf(buffer,"RRT NOK\n");
						i=write(newfd,buffer,strlen(buffer));
						if(i==-1) exit(1);
						if(s.v == 1)
							printf("Message sent{%s}\n%s:User is not subscribed or invalid mid\n",buffer,tempUID);
						close(newfd);
						break;
					}

					list = (GROUPLIST*)malloc(sizeof(GROUPLIST)*100);
					i=ListGroupsDir(list);
					aux=0;
					//Ver qual o ultimo mid do grupo
					while(aux<i){
						if(strcmp(list->group_no[aux],tempGID)==0){
							strcpy(mid,list->mid[aux]);
						}
						aux++;
					}
					free(list);

					msg_no=atoi(mid)-atoi(tempMID)+1;//numero mensagens a enviar

					if(msg_no <= 0){
						sprintf(buffer,"RRT EOF\n");
						i=write(newfd,buffer,strlen(buffer));
						if(i==-1) exit(1);
						if(s.v == 1)
							printf("Message sent{%s}\n%s:There are no messages available\n",buffer,tempMID);
						close(newfd);
						break;
					}

					if(msg_no > 20)
						msg_no=20;


					bzero(buffer,BUFFERSIZE);
					sprintf(buffer,"RRT OK %d",msg_no);
					
					i = write(newfd,buffer,strlen(buffer));
					if(i==-1) exit(1);

					aux=0;

					sprintf(path,"./GROUPS/%s/MSG",tempGID);

					/* Ver ficheiros na diretoria do path */
					struct dirent **files;
					int n = scandir(path, &files, NULL, alphasort);
					if (n < 0) {
						fprintf(stderr,
							"Cannot open %s (%s)\n", path, strerror(errno));
						exit(EXIT_FAILURE);
					}
					
					for(int a=atoi(tempMID); a <= msg_no+atoi(tempMID); a++){
						if(files[a]->d_name[0]=='.')
							continue;
						if(files[a]->d_type == DT_REG)
							continue;
						bzero(mid,MIDSIZE);
						strcpy(mid,files[a]->d_name);
						if(atoi(mid)< atoi(tempMID)){
							continue;
						}
						bzero(path,50);
						bzero(author,UIDSIZE);
						bzero(text,MAXTSIZE);
						sprintf(path,"./GROUPS/%s/MSG/%s/A U T H O R.txt",tempGID,mid);
						fp=fopen(path,"r");
						fread(author,UIDSIZE,1,fp);
						fclose(fp);

						bzero(path,50);
						sprintf(path,"./GROUPS/%s/MSG/%s/T E X T.txt",tempGID,mid);
						fp=fopen(path,"r");
						fseek(fp,0,SEEK_END);
						textsize = ftell(fp);
						fseek(fp,0,SEEK_SET);
						aux=0;
						while(aux < textsize){
							c=fgetc(fp);
							strncat(text,&c,1);
							aux++;
						}
						fclose(fp);
						bzero(buffer,BUFFERSIZE);
						
						sprintf(buffer," %s %s %d %s",mid,author,textsize,text);

						if(s.v==1)
							printf("%s:Retrieved: \"%s\"",tempUID,text);

						i = write(newfd,buffer,strlen(buffer));
						if(i==-1) exit(1);

						bzero(path,50);
						sprintf(path,"./GROUPS/%s/MSG/%s",tempGID,mid);
						auxd = opendir(path);
						if(auxd){
							while((auxdir=readdir(auxd))!=NULL){
								if(auxdir->d_name[0]=='.')
									continue;
								//caso em que ha ficheiro
								if(strncmp(auxdir->d_name,"A U T H O R.txt",15)!=0 && strncmp(auxdir->d_name,"T E X T.txt",11)!=0){
									bzero(path,50);
									bzero(fname,MAXFNAME);
									strcpy(fname,auxdir->d_name);
									
									sprintf(path,"./GROUPS/%s/MSG/%s/%s",tempGID,mid,fname);
									fp = fopen(path,"r");
									fseek(fp,0,SEEK_END);
									filesize=0;
									filesize = ftell(fp);
									fseek(fp,0,SEEK_SET);

									bzero(buffer,BUFFERSIZE);
									sprintf(buffer," / %s %d ",fname,filesize);
									i = write(newfd,buffer,strlen(buffer));
									if(i==-1) exit(1);

									while(filesize > 0){
										c=fgetc(fp);
										
										filesize--;
										i=write(newfd,&c,1);
										if(i==-1) exit(1);	
									}

									if(s.v == 1)
										printf(" %s",fname);
									fclose(fp);
								}
							}
							closedir(auxd);
						}
						else
							return -1;
						if(s.v == 1)
							printf("\n");
						
					}

					i = write(newfd,"\n",1);
					if(i==-1) exit(1);
				
					for (int b = 0; b < n; b++) {
						free(files[b]);
					}
					free(files);

					close(newfd);
					break;		

			}
		}
		freeaddrinfo(res);
		close(fd);
	}
	return 0;
}

Server processInput(int argc, char** argv)
{
	Server s;

	if (argc!=1 && argc!=2 && argc!=3 && argc!=4){
		exit(EXIT_FAILURE);
	}

	s.v=0;
	strcpy(s.DSport,PORT);

	if(argc == 2 && strcmp(argv[1], "-v")==0){
		s.v = 1;
	}

	if (argc >= 3){
		if (strcmp(argv[1], "-p") == 0){//Caso em que foi especificado port e este vem primeiro
			strcpy(s.DSport, argv[2]);
			if (argc==4 && strcmp(argv[3], "-v")==0){//Caso em que foi especificado -v
				s.v = 1;
			}
		}
		if (strcmp(argv[1], "-v") == 0){//Caso em que foi especificado -v primeiro
			s.v = 1;
			if (argc==4 && strcmp(argv[2], "-p")==0){//Caso em que foi especificado port
				strcpy(s.DSport, argv[3]);
			}
		}
	}

	return s;
}

int getCommand(char* cmd)
{
	if (strcmp(cmd, "REG")==0){
		return 0;
	}
	if (strcmp(cmd, "UNR")==0){
		return 1;
	}
	if (strcmp(cmd, "LOG")==0){
		return 2;
	}
	if (strcmp(cmd, "OUT")==0){
		return 3;
	}
	if (strcmp(cmd, "GLS")==0){
		return 4;
	}
	if (strcmp(cmd, "GSR")==0){
		return 5;
	}
	if (strcmp(cmd, "GUR")==0){
		return 6;
	}
	if (strcmp(cmd, "GLM")==0){
		return 7;
	}
	if (strcmp(cmd, "ULS")==0){
		return 8;
	}
	if (strcmp(cmd, "PST")==0){
		return 9;
	}
	if (strcmp(cmd, "RTV")==0){
		return 10;
	}

	return -1;
}

int CreateUserDir(char *UID, char *PW){
	char user_dirname[20];
	char file[30];
	int ret;
	FILE *ptr;
	struct stat st = {0};

	sprintf(user_dirname,"./USERS/%s",UID);

	if (stat(user_dirname, &st) == -1) {//Ver se diretoria do user ja existe
		ret=mkdir(user_dirname,0700);
		if(ret==-1)
			return(0);
		sprintf(file,"%s/%s_pass.txt",user_dirname,UID);
		ptr = fopen(file,"w");
		fwrite(PW,1,strlen(PW),ptr);
		fclose(ptr);
	}
	else{
		return 2;
	}
	return(1);
}

int DelUserDir(char *UID,char *PW){
	char user_dirname[20];
	char fileloginpath[50];
	int n;
	struct stat st = {0};
	sprintf(user_dirname,"./USERS/%s",UID);

	if(stat(user_dirname,&st) == -1){//Caso em que user nao existe
		return 0;
	}

	sprintf(fileloginpath,"./USERS/%s/%s_login.txt",UID,UID);

	if(stat(fileloginpath,&st) == -1){//Caso em que login.txt nao existe
		n=DelFile(UID,PW,"pass");
		if(n==0){
			return 0;
		}
		if(rmdir(user_dirname)==0)
			return(1);
		else
			return(0);
	}
	else{//Caso em que login.txt existe
		n=DelFile(UID,PW,"login");
		if(n==0){
			return 0;
		}
	}
	
	n=DelFile(UID,PW,"pass");

	if(n==0){
		return 0;
	}
	if(rmdir(user_dirname)==0)
		return(1);
	else
		return(0);
}

int DelFile(char *UID,char *PW,char *type){
	char pathnamepass[50];
	char pathname[50];
	char temppw[9];
	FILE *ptr;

	sprintf(pathnamepass,"./USERS/%s/%s_pass.txt",UID,UID);

	ptr = fopen(pathnamepass,"r");
	fread(temppw,8,1,ptr);
	fclose(ptr);

	if(strncmp(temppw,PW,MAXPW-1)!=0){
		return(0);
	}

	sprintf(pathname,"./USERS/%s/%s_%s.txt",UID,UID,type);
	if(unlink(pathname)==0)//Delete login or pass file
		return(1);
	else
		return(0);
}

int Login(char *UID,char *PW){
	char user_dirname[20];
	char filelogin[50];
	char pathname[50];
	char temppw[9];
	struct stat st = {0};
	FILE *ptr;

	sprintf(user_dirname,"./USERS/%s",UID);
	if(stat(user_dirname,&st) == -1){//Caso em que user nao existe
		return 0;
	}
	sprintf(pathname,"./USERS/%s/%s_pass.txt",UID,UID);
	ptr = fopen(pathname,"r");
	fread(temppw,8,1,ptr);
	fclose(ptr);

	if(strncmp(temppw,PW,MAXPW-1)!=0){
		return 0;
	}
	sprintf(filelogin,"./USERS/%s/%s_login.txt",UID,UID);
	ptr = fopen(filelogin,"a");//Criat ficheiro login
	fclose(ptr);
	return 1;
}

void swap(char *x, char*y){//Trocar de posicao dois elementos da GROUPLIST
	char tmp[24];
	strcpy(tmp,x);
	strcpy(x,y);
	strcpy(y,tmp);
}

void SortGList(GROUPLIST *list, int n){//Bubblesort
	int i, j;
   	for (i = 0; i < n-1; i++){     
       for (j = 0; j < n-i-1; j++){
           if (atoi(list->group_no[j]) > atoi(list->group_no[j+1])){
			   swap(list->group_no[j], list->group_no[j+1]);
			   swap(list->group_name[j], list->group_name[j+1]);
			   swap(list->mid[j], list->mid[j+1]);
		   }
	   }
	}
}

int ListGroupsDir(GROUPLIST *list){//Criar uma lista com todos os grupos criados no momento
	DIR *d, *aux;
	struct dirent *dir, *auxdir;
	int i=0;
	FILE *fp;
	char GIDname[50];
	char MSG[50];
	char gid[3];
	list->no_groups=0;
	
	d = opendir("./GROUPS");
	if (d){
		while ((dir = readdir(d)) != NULL){
			if(dir->d_name[0]=='.')
				continue;
			if(strlen(dir->d_name)>2)
				continue;

			strcpy(gid,dir->d_name);
			strcpy(list->group_no[i], gid);
			sprintf(GIDname,"./GROUPS/%s/%s_name.txt",gid,gid);
			fp=fopen(GIDname,"r");
			if(fp){
				fscanf(fp,"%24s",list->group_name[i]);
				fclose(fp);
			}
			sprintf(MSG,"./GROUPS/%s/MSG",gid);
			aux = opendir(MSG);
			if(aux){
				int maxmsg=0;
				while ((auxdir = readdir(aux)) != NULL){
					if(auxdir->d_name[0]=='.')
						continue;
					maxmsg++;
				}
				sprintf(list->mid[i],"%d",maxmsg);
				if(strlen(list->mid[i])==1){
					sprintf(list->mid[i],"000%d",maxmsg);
				}
				else if(strlen(list->mid[i])==2){
					sprintf(list->mid[i],"00%d",maxmsg);
				}
				else if(strlen(list->mid[i])==3){
					sprintf(list->mid[i],"0%d",maxmsg);
				}
				closedir(aux);
			}
			++i;
			if(i==99)
				break;
		}
		
		list->no_groups=i;
		closedir(d);
	}
	else
		return(-1);

	if(list->no_groups>1)
		SortGList(list,list->no_groups);


	return(list->no_groups);
}

int ListUsersDir(char* UID){//Ver se user esta login
	DIR *d;
	struct dirent *dir;
	char loginpath[50];
	d = opendir("./USERS");
	if(d) {
		while((dir = readdir(d))!= NULL){
			if(strcmp(dir->d_name,UID)==0){
				sprintf(loginpath,"./USERS/%s/%s_login.txt",UID,UID);
				if(access(loginpath,F_OK)==0){
					closedir(d);
					return 1;
				}
				else{
					closedir(d);
					return 0;
				}
			}
		}
		closedir(d);
	}

	return 0;
}

int creategroup(char *UID,char *GNAME){
	char groupdirname[50];
	char pathgname[72];
	char msgdir[54];
	GROUPLIST* auxlist;
	int auxlastgid;
	FILE *ptr;

	auxlist = (GROUPLIST*)malloc(sizeof(GROUPLIST)*100);
	auxlastgid=ListGroupsDir(auxlist);
	free(auxlist);
	auxlastgid++;

	if(auxlastgid > 99)
		return 0;
	if(auxlastgid<10){
		sprintf(groupdirname,"./GROUPS/0%d",auxlastgid);
	}
	else{
		sprintf(groupdirname,"./GROUPS/%d",auxlastgid);
	}
	
	mkdir(groupdirname,0700);
	if(auxlastgid > 9){
		sprintf(pathgname,"%s/%d_name.txt",groupdirname,auxlastgid);
	}
	else{
		sprintf(pathgname,"%s/0%d_name.txt",groupdirname,auxlastgid);
	}
	ptr=fopen(pathgname,"w");
	fwrite(GNAME,1,strlen(GNAME),ptr);
	fclose(ptr);

	sprintf(msgdir,"%s/MSG",groupdirname);
	mkdir(msgdir,0700);

	return 1;
}

void CreateGroupUser(char *UID, char *GID){//Subscrever user ao grupo
	char userpath[50];
	FILE *ptr;
	sprintf(userpath,"./GROUPS/%s/%s.txt",GID,UID);
	ptr = fopen(userpath,"a");
	fclose(ptr);
}

int checkGroupUser(char *UID,char *GID){//Verificar se user esta subscrito ao grupo
	char gidpath[50];
	sprintf(gidpath,"./GROUPS/%s/%s.txt",GID,UID);
	if(access(gidpath,F_OK)==0){
		return 1;
	}
	else{
		return 0;
	}
}

void UnsubscribeGroupUser(char *UID,char *GID){//Desinscrever user do grupo
	char pathuser[50];
	
	sprintf(pathuser,"./GROUPS/%s/%s.txt",GID,UID);
	unlink(pathuser);
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