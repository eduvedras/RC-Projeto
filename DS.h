#ifndef DS_H
#define DS_H

#define PORT "58001"
#define IPSIZE 25
#define PORTSIZE 6
#define MAXCMD 12
#define MAXPW 9
#define MAXGROUPS 101
#define MAXGNAME 25
#define MAXTSIZE 241
#define MAXFNAME 26
#define MAXGROUPSMSG 3308
#define UIDSIZE 6
#define GIDSIZE 3
#define MIDSIZE 5
#define MAXFDIGITSIZE 11
#define BUFFERSIZE 8000


typedef struct server
{
	char DSport[PORTSIZE];
    int v;

} Server;

typedef struct grouplist{
    int no_groups;
    char group_no[100][3];
    char group_name[100][25];
    char mid[100][5];
} GROUPLIST;

typedef struct userlist{
    int no_users;
    char *UID;
    int *isloggedin;
} USERLIST;

Server processInput(int argc, char** argv);

int getCommand(char* cmd);

int CreateUserDir(char *UID,char *PW);

int DelUserDir(char *UID,char *PW);

int DelFile(char *UID,char *PW,char *type);

int Login(char *UID,char * PW);

void SortGList(GROUPLIST *list,int n);

int ListGroupsDir(GROUPLIST *list);

int ListUsersDir(char* UID);

int creategroup(char *UID,char *GNAME);

void CreateGroupUser(char *UID, char *GID);

int checkGroupUser(char *UID,char *GID);

void UnsubscribeGroupUser(char *UID, char *GID);

int TimerON(int sd);

int TimerOFF(int sd);

#endif