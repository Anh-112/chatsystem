/*
 * chat_server.c  - Multi-client TCP chat server
 * SHA1 auth + substitution cipher via kernel driver (with pure-C fallback)
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include "chat_server.h"
#include "crypto_lib.h"

/* ── simple JSON helpers ─────────────────────────────────────── */
static int jget_str(const char *j, const char *k, char *out, int n) {
    char s[128]; snprintf(s,sizeof(s),"\"%s\":",k);
    const char *p=strstr(j,s); if(!p) return 0;
    p+=strlen(s); while(*p==' ')p++;
    if(*p!='"') return 0; p++;
    int i=0;
    while(*p&&*p!='"'&&i<n-1) {
        if(*p=='\\') {
            p++;
            if(*p=='"') out[i++]='"';
            else if(*p=='\\') out[i++]='\\';
            else if(*p=='/') out[i++]='/';
            else if(*p=='b') out[i++]='\b';
            else if(*p=='f') out[i++]='\f';
            else if(*p=='n') out[i++]='\n';
            else if(*p=='r') out[i++]='\r';
            else if(*p=='t') out[i++]='\t';
            else if(*p=='u') {
                // Skip unicode for now
                p+=4;
            }
            p++;
        } else {
            out[i++]=*p++;
        }
    }
    out[i]='\0'; return 1;
}
static int jget_int(const char *j, const char *k, int *out) {
    char s[128]; snprintf(s,sizeof(s),"\"%s\":",k);
    const char *p=strstr(j,s); if(!p) return 0;
    p+=strlen(s); while(*p==' ')p++;
    *out=atoi(p); return 1;
}
static void json_escape(const char *in, char *out, int n){
    static const char *hex = "0123456789abcdef";
    int o = 0;
    while(*in && o < n-1){
        unsigned char c = (unsigned char)*in++;
        if(c == '"' || c == '\\'){
            if(o + 2 >= n-1) break;
            out[o++] = '\\'; out[o++] = c;
        } else if(c == '\b'){
            if(o + 2 >= n-1) break; out[o++] = '\\'; out[o++] = 'b';
        } else if(c == '\f'){
            if(o + 2 >= n-1) break; out[o++] = '\\'; out[o++] = 'f';
        } else if(c == '\n'){
            if(o + 2 >= n-1) break; out[o++] = '\\'; out[o++] = 'n';
        } else if(c == '\r'){
            if(o + 2 >= n-1) break; out[o++] = '\\'; out[o++] = 'r';
        } else if(c == '\t'){
            if(o + 2 >= n-1) break; out[o++] = '\\'; out[o++] = 't';
        } else if(c < 0x20){
            if(o + 6 >= n-1) break;
            out[o++] = '\\'; out[o++] = 'u'; out[o++] = '0'; out[o++] = '0';
            out[o++] = hex[(c >> 4) & 0xF];
            out[o++] = hex[c & 0xF];
        } else {
            out[o++] = c;
        }
    }
    out[o] = '\0';
}
static void mkpkt(char *b,int n,int type,const char *from,const char *to,
                  int tt,const char *content,const char *tok,const char *ex){
    char ef[MAX_NAME_LEN*2];
    char et[MAX_NAME_LEN*2];
    char ec[MAX_MSG_LEN*6];
    char etok[130];
    char eex[130];
    json_escape(from?from:"", ef, sizeof(ef));
    json_escape(to?to:"", et, sizeof(et));
    json_escape(content?content:"", ec, sizeof(ec));
    json_escape(tok?tok:"", etok, sizeof(etok));
    json_escape(ex?ex:"", eex, sizeof(eex));
    snprintf(b,n,"{\"type\":%d,\"from\":\"%s\",\"to\":\"%s\","
        "\"target_type\":%d,\"content\":\"%s\","
        "\"token\":\"%s\",\"extra\":\"%s\"}\n",
        type,ef,et,tt,ec,etok,eex);
}

/* ── globals ─────────────────────────────────────────────────── */
static Client  clients[MAX_CLIENTS];
static Room    rooms[MAX_ROOMS];
static int     room_count=0;
static pthread_mutex_t mu=PTHREAD_MUTEX_INITIALIZER;
static int     crypto_fd=-1, use_drv=0;

/* ── crypto wrappers ─────────────────────────────────────────── */
static void do_sha1(const char *in, char *out){
    if(use_drv && crypto_sha1(crypto_fd,in,out)==0) return;
    fallback_sha1(in,out);
}
static void do_enc(const char *plain, char *cipher){
    int l=strlen(plain);
    if(use_drv && crypto_encrypt(crypto_fd,plain,cipher,CIPHER_KEY)>=0) return;
    fallback_encrypt(plain,cipher,l,CIPHER_KEY);
}
static void do_dec(const char *cipher, char *plain){
    int l=strlen(cipher);
    if(use_drv && crypto_decrypt(crypto_fd,cipher,plain,CIPHER_KEY)>=0) return;
    fallback_decrypt(cipher,plain,l,CIPHER_KEY);
}

/* ── token ───────────────────────────────────────────────────── */
static void gen_tok(char *o){
    const char c[]="abcdefghijklmnopqrstuvwxyz0123456789";
    for(int i=0;i<32;i++) o[i]=c[rand()%(sizeof(c)-1)];
    o[32]='\0';
}

/* ── user DB ─────────────────────────────────────────────────── */
static int db_find(const char *u, char *h){
    FILE *f=fopen("users.db","r"); if(!f) return 0;
    char ln[256];
    while(fgets(ln,sizeof(ln),f)){
        ln[strcspn(ln,"\n")]='\0';
        char *col=strchr(ln,':'); if(!col) continue;
        *col='\0';
        if(strcmp(ln,u)==0){if(h)strcpy(h,col+1);fclose(f);return 1;}
    }
    fclose(f); return 0;
}
static int db_add(const char *u, const char *h){
    if(db_find(u,NULL)) return 0;
    FILE *f=fopen("users.db","a"); if(!f) return 0;
    fprintf(f,"%s:%s\n",u,h); fclose(f); return 1;
}
static void hist_save(const char *fr,const char *to,int tt,const char *msg){
    FILE *f=fopen("history.db","a"); if(!f) return;
    time_t t=time(NULL); char ts[32];
    strftime(ts,sizeof(ts),"%Y-%m-%d %H:%M:%S",localtime(&t));
    fprintf(f,"%s|%d|%s|%s|%s\n",ts,tt,fr,to,msg); fclose(f);
}

/* ── client helpers ──────────────────────────────────────────── */
static Client *find_fd(int fd){
    for(int i=0;i<MAX_CLIENTS;i++) if(clients[i].fd==fd) return &clients[i];
    return NULL;
}
static Client *find_nm(const char *n){
    for(int i=0;i<MAX_CLIENTS;i++)
        if(clients[i].fd>0&&strcmp(clients[i].username,n)==0) return &clients[i];
    return NULL;
}
static Client *alloc_cl(int fd){
    for(int i=0;i<MAX_CLIENTS;i++)
        if(clients[i].fd<=0){memset(&clients[i],0,sizeof(Client));clients[i].fd=fd;return &clients[i];}
    return NULL;
}
static void free_cl(int fd){Client *c=find_fd(fd);if(c)memset(c,0,sizeof(Client));}

/* ── broadcast danh sách user online tới tất cả client ───── */
static void broadcast_userlist(void){
    char buf[4096]=""; int first=1;
    for(int i=0;i<MAX_CLIENTS;i++){
        if(clients[i].fd>0&&clients[i].logged_in){
            if(!first) strcat(buf,"|");
            strcat(buf,clients[i].username);
            first=0;
        }
    }
    char pkt[5000]; mkpkt(pkt,sizeof(pkt),PKT_OK,"server","",0,buf,"","users");
    for(int i=0;i<MAX_CLIENTS;i++)
        if(clients[i].fd>0&&clients[i].logged_in)
            send(clients[i].fd,pkt,strlen(pkt),MSG_NOSIGNAL);
}

/* ── send helpers ────────────────────────────────────────────── */
static void snd(int fd,const char *m){ send(fd,m,strlen(m),MSG_NOSIGNAL); }
static void snd_ok(int fd,const char *d,const char *t){
    char b[512]; mkpkt(b,sizeof(b),PKT_OK,"server","",0,d,t,""); snd(fd,b);
}
static void snd_err(int fd,const char *d){
    char b[512]; mkpkt(b,sizeof(b),PKT_ERROR,"server","",0,d,"",""); snd(fd,b);
}

/* ── room helpers ────────────────────────────────────────────── */
static Room *find_room(const char *n){
    for(int i=0;i<room_count;i++) if(strcmp(rooms[i].name,n)==0) return &rooms[i];
    return NULL;
}
static Room *alloc_room(const char *n,const char *cr){
    if(room_count>=MAX_ROOMS) return NULL;
    Room *r=&rooms[room_count++]; memset(r,0,sizeof(Room));
    r->id=room_count; strncpy(r->name,n,MAX_NAME_LEN-1); strncpy(r->creator,cr,MAX_NAME_LEN-1);
    return r;
}
static int room_has(Room *r,int fd){
    for(int i=0;i<r->member_count;i++)
        if(r->member_fds[i]==fd) return 1;
    return 0;
}
static void room_add(Room *r,int fd){
    if(r->member_count>=MAX_ROOM_MEMBERS || room_has(r,fd)) return;
    r->member_fds[r->member_count++]=fd;
}
static void room_rem(Room *r,int fd){
    for(int i=0;i<r->member_count;i++){
        if(r->member_fds[i]==fd){
            r->member_fds[i]=r->member_fds[--r->member_count];
            i--; /* remove duplicates if any */
        }
    }
}

/* ── handlers ────────────────────────────────────────────────── */
static void h_register(int fd,const char *j){
    char u[MAX_NAME_LEN],p[MAX_PASS_LEN];
    if(!jget_str(j,"from",u,sizeof(u))||!jget_str(j,"content",p,sizeof(p))){snd_err(fd,"bad_pkt");return;}
    char hash[SHA1_HEX_SIZE]; do_sha1(p,hash);
    pthread_mutex_lock(&mu);
    int ok=db_add(u,hash);
    pthread_mutex_unlock(&mu);
    LOG("REGISTER %s: %s hash=%s", u, ok?"ok":"fail", hash);
    ok ? snd_ok(fd,"registered","") : snd_err(fd,"user_exists");
}

static void h_login(int fd,const char *j){
    char u[MAX_NAME_LEN],p[MAX_PASS_LEN];
    if(!jget_str(j,"from",u,sizeof(u))||!jget_str(j,"content",p,sizeof(p))){snd_err(fd,"bad_pkt");return;}
    char sh[SHA1_HEX_SIZE]; do_sha1(p,sh);
    char stored[SHA1_HEX_SIZE];
    if(!db_find(u,stored)){snd_err(fd,"user_not_found");return;}
    if(strcmp(sh,stored)!=0){snd_err(fd,"wrong_password");return;}
    char tok[65]={0};
    pthread_mutex_lock(&mu);
    Client *c=find_fd(fd);
    if(c){strncpy(c->username,u,MAX_NAME_LEN-1);c->logged_in=1;gen_tok(c->token);strcpy(tok,c->token);}
    pthread_mutex_unlock(&mu);
    LOG("LOGIN %s tok=%s",u,tok);
    snd_ok(fd,"logged_in",tok);
    pthread_mutex_lock(&mu);
    broadcast_userlist();
    pthread_mutex_unlock(&mu);
}

static void h_send(int fd,const char *j){
    char from[MAX_NAME_LEN],to[MAX_NAME_LEN],content[MAX_MSG_LEN],tok[65];
    int tt=0;
    jget_str(j,"from",from,sizeof(from));
    jget_str(j,"to",to,sizeof(to));
    jget_str(j,"content",content,sizeof(content));
    jget_str(j,"token",tok,sizeof(tok));
    jget_int(j,"target_type",&tt);

    pthread_mutex_lock(&mu);
    Client *s=find_fd(fd);
    int auth=s&&s->logged_in&&strcmp(s->token,tok)==0;
    pthread_mutex_unlock(&mu);
    if(!auth){snd_err(fd,"unauthorized");return;}

    char plain[MAX_MSG_LEN]; do_dec(content,plain);
    hist_save(from,to,tt,plain);
    LOG("MSG %s->%s: %s",from,to,plain);

    char cipher[MAX_MSG_LEN]; do_enc(plain,cipher);
    char pkt[MAX_MSG_LEN*6 + 512];
    mkpkt(pkt,sizeof(pkt),PKT_RECV_MSG,from,to,tt,cipher,"","");

    if(tt==TARGET_USER){
        pthread_mutex_lock(&mu);
        Client *d=find_nm(to);
        if(d) snd(d->fd,pkt); else snd_err(fd,"user_offline");
        snd(fd,pkt);
        pthread_mutex_unlock(&mu);
    } else {
        pthread_mutex_lock(&mu);
        Room *r=find_room(to);
        if(r){
            // Gửi cho tất cả members TRỪ người gửi
            for(int i=0;i<r->member_count;i++){
                if(r->member_fds[i] != fd) // Không gửi cho người gửi
                    snd(r->member_fds[i],pkt);
            }
            // Gửi lại cho người gửi để đảm bảo
            snd(fd,pkt);
        } else {
            snd_err(fd,"room_not_found");
        }
        pthread_mutex_unlock(&mu);
    }
}

static void h_create_room(int fd,const char *j){
    char tok[65],nm[MAX_NAME_LEN];
    jget_str(j,"token",tok,sizeof(tok)); jget_str(j,"content",nm,sizeof(nm));
    pthread_mutex_lock(&mu);
    Client *c=find_fd(fd);
    int ok=c&&c->logged_in&&strcmp(c->token,tok)==0;
    if(ok){Room *r=alloc_room(nm,c->username);if(r)room_add(r,fd);else ok=0;}
    pthread_mutex_unlock(&mu);
    ok?snd_ok(fd,"room_created",""):snd_err(fd,"room_error");
}

static void h_join_room(int fd,const char *j){
    char tok[65],nm[MAX_NAME_LEN];
    jget_str(j,"token",tok,sizeof(tok)); jget_str(j,"content",nm,sizeof(nm));
    pthread_mutex_lock(&mu);
    Client *c=find_fd(fd);
    int ok=c&&c->logged_in&&strcmp(c->token,tok)==0;
    if(ok){
        Room *r=find_room(nm); if(!r) r=alloc_room(nm,c->username);
        if(r) room_add(r,fd); else ok=0;
    }
    pthread_mutex_unlock(&mu);
    ok?snd_ok(fd,"joined_room",""):snd_err(fd,"room_error");
}

static void h_leave_room(int fd,const char *j){
    char tok[65],nm[MAX_NAME_LEN];
    jget_str(j,"token",tok,sizeof(tok)); jget_str(j,"content",nm,sizeof(nm));
    pthread_mutex_lock(&mu);
    Client *c=find_fd(fd);
    if(c&&c->logged_in&&strcmp(c->token,tok)==0){
        Room *r=find_room(nm); if(r) room_rem(r,fd);
    }
    pthread_mutex_unlock(&mu);
    snd_ok(fd,"left_room","");
}

static void h_list_users(int fd,const char *j){
    char buf[4096]=""; int first=1;
    pthread_mutex_lock(&mu);
    for(int i=0;i<MAX_CLIENTS;i++){
        if(clients[i].fd>0&&clients[i].logged_in){
            if(!first) strcat(buf,"|");
            strcat(buf,clients[i].username);
            first=0;
        }
    }
    pthread_mutex_unlock(&mu);
    char pkt[5000]; mkpkt(pkt,sizeof(pkt),PKT_OK,"server","",0,buf,"","users");
    snd(fd,pkt);
}

static void h_list_rooms(int fd,const char *j){
    char buf[4096]="";
    pthread_mutex_lock(&mu);
    for(int i=0;i<room_count;i++){
        if(i>0) strcat(buf,"|");
        strcat(buf,rooms[i].name);
    }
    pthread_mutex_unlock(&mu);
    char pkt[5000]; mkpkt(pkt,sizeof(pkt),PKT_OK,"server","",0,buf,"","rooms");
    snd(fd,pkt);
}

static void dispatch(int fd,char *j){
    int type=0; jget_int(j,"type",&type);
    switch(type){
    case PKT_REGISTER:    h_register(fd,j);    break;
    case PKT_LOGIN:       h_login(fd,j);       break;
    case PKT_SEND_MSG:    h_send(fd,j);        break;
    case PKT_CREATE_ROOM: h_create_room(fd,j); break;
    case PKT_JOIN_ROOM:   h_join_room(fd,j);   break;
    case PKT_LEAVE_ROOM:  h_leave_room(fd,j);  break;
    case PKT_LIST_USERS:  h_list_users(fd,j);  break;
    case PKT_LIST_ROOMS:  h_list_rooms(fd,j);  break;
    case PKT_PING:        snd_ok(fd,"pong","");break;
    default: snd_err(fd,"unknown_type");
    }
}

/* ── per-client thread ───────────────────────────────────────── */
typedef struct { int fd; } ThreadArg;

static void *client_thread(void *arg){
    int fd=((ThreadArg*)arg)->fd; free(arg);
    char buf[MAX_MSG_LEN*2]; int pos=0;

    while(1){
        int n=recv(fd,buf+pos,sizeof(buf)-pos-1,0);
        if(n<=0){ LOG("Client %d disconnected",fd); break; }
        pos+=n; buf[pos]='\0';
        char *nl;
        while((nl=strchr(buf,'\n'))!=NULL){
            *nl='\0';
            if(strlen(buf)>0) dispatch(fd,buf);
            int rem=pos-(nl-buf+1);
            memmove(buf,nl+1,rem); pos=rem; buf[pos]='\0';
        }
        if(pos>=sizeof(buf)-1) pos=0; /* overflow protection */
    }
    pthread_mutex_lock(&mu);
    free_cl(fd);
    broadcast_userlist();
    pthread_mutex_unlock(&mu);
    close(fd);
    return NULL;
}

/* ── main ────────────────────────────────────────────────────── */
int main(void){
    srand(time(NULL));

    /* try opening kernel driver */
    crypto_fd=crypto_open();
    use_drv=(crypto_fd>=0);
    LOG("Crypto driver: %s", use_drv?"KERNEL":"fallback (pure-C)");

    int srv=socket(AF_INET,SOCK_STREAM,0);
    if(srv<0){perror("socket");return 1;}
    int opt=1; setsockopt(srv,SOL_SOCKET,SO_REUSEADDR,&opt,sizeof(opt));

    struct sockaddr_in addr={.sin_family=AF_INET,.sin_port=htons(SERVER_PORT),.sin_addr.s_addr=INADDR_ANY};
    if(bind(srv,(struct sockaddr*)&addr,sizeof(addr))<0){perror("bind");return 1;}
    if(listen(srv,16)<0){perror("listen");return 1;}

    LOG("Chat server listening on port %d",SERVER_PORT);

    while(1){
        struct sockaddr_in ca; socklen_t cl=sizeof(ca);
        int fd=accept(srv,(struct sockaddr*)&ca,&cl);
        if(fd<0){perror("accept");continue;}
        LOG("New connection fd=%d ip=%s",fd,inet_ntoa(ca.sin_addr));
        pthread_mutex_lock(&mu);
        Client *c=alloc_cl(fd);
        pthread_mutex_unlock(&mu);
        if(!c){close(fd);continue;}
        ThreadArg *ta=malloc(sizeof(ThreadArg)); ta->fd=fd;
        pthread_t t; pthread_create(&t,NULL,client_thread,ta);
        pthread_detach(t);
    }
    if(use_drv) crypto_close(crypto_fd);
    return 0;
}
