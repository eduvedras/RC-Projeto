#ifndef USER_H
#define USER_H

#define PORT "58001"
#define IPSIZE 25
#define PORTSIZE 6
#define MAXCMD 12
#define MAXPW 9
#define MAXGROUPS 101
#define MAXGNAME 25
#define MAXTSIZE 242
#define MAXFNAME 26
#define MAXGROUPSMSG 3308
#define UIDSIZE 6
#define GIDSIZE 3
#define MAXFDIGITSIZE 11
#define BUFFERSIZE 8000


typedef struct user
{
	char DSIP[IPSIZE];
	char DSPort[PORTSIZE];
    char UID[UIDSIZE];
    char PW[MAXPW];

} User;

User processInput(int argc, char** argv);

int getCommand(char* cmd);

void initUDP();

void initTCP();

int TimerON(int sd);

int TimerOFF(int sd);


#endif