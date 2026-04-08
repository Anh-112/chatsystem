/*
 * chat_client.c  - Terminal client for CryptoChat server
 * Usage: ./chat_client [host] [port]
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <termios.h>

#include "chat_server.h"
#include "crypto_lib.h"

static int    g_fd   = -1;
static int    g_drv  = -1;
static char   g_user[MAX_NAME_LEN];
static char   g_tok[65];
static char   g_active_to[MAX_NAME_LEN];
static int    g_active_ttype = 1;
static volatile int g_running = 1;
static volatile int g_logged_in = 0;
static int g_manual_user_request = 0;

/* ── crypto ───────────────────────────────────────────────── */
static void do_enc(const char *p, char *c){
    int l=strlen(p);
    if(g_drv>=0 && crypto_encrypt(g_drv,p,c,CIPHER_KEY)>=0) return;
    fallback_encrypt(p,c,l,CIPHER_KEY);
}
static void do_dec(const char *c, char *p){
    int l=strlen(c);
    if(g_drv>=0 && crypto_decrypt(g_drv,c,p,CIPHER_KEY)>=0) return;
    fallback_decrypt(c,p,l,CIPHER_KEY);
}
static void do_sha1(const char *in, char *out){
    if(g_drv>=0 && crypto_sha1(g_drv,in,out)==0) return;
    fallback_sha1(in,out);
}

/* ── JSON helpers ─────────────────────────────────────────── */
static int jget(const char *j,const char *k,char *out,int n){
    char s[128]; snprintf(s,sizeof(s),"\"%s\":",k);
    const char *p=strstr(j,s); if(!p) return 0;
    p+=strlen(s); while(*p==' ')p++;
    if(*p!='"') return 0; p++;
    int i=0; while(*p&&*p!='"'&&i<n-1) out[i++]=*p++;
    out[i]='\0'; return 1;
}
static int jgeti(const char *j,const char *k,int *o){
    char s[128]; snprintf(s,sizeof(s),"\"%s\":",k);
    const char *p=strstr(j,s); if(!p) return 0;
    p+=strlen(s); while(*p==' ')p++;
    *o=atoi(p); return 1;
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

/* ── net ──────────────────────────────────────────────────── */
static void snd_raw(const char *m){ send(g_fd,m,strlen(m),MSG_NOSIGNAL); }

static void send_pkt(int type,const char *from,const char *to,int tt,
                     const char *content,const char *tok,const char *extra){
    char buf[MAX_MSG_LEN*6 + 256];
    char ef[MAX_NAME_LEN*2];
    char et[MAX_NAME_LEN*2];
    char ec[MAX_MSG_LEN*6];
    char etok[130];
    char eextra[130];
    json_escape(from?from:"", ef, sizeof(ef));
    json_escape(to?to:"", et, sizeof(et));
    json_escape(content?content:"", ec, sizeof(ec));
    json_escape(tok?tok:"", etok, sizeof(etok));
    json_escape(extra?extra:"", eextra, sizeof(eextra));
    snprintf(buf,sizeof(buf),
        "{\"type\":%d,\"from\":\"%s\",\"to\":\"%s\","
        "\"target_type\":%d,\"content\":\"%s\","
        "\"token\":\"%s\",\"extra\":\"%s\"}\n",
        type,ef,et,tt,ec,etok,eextra);
    snd_raw(buf);
}

/* ── refresh thread (auto-update user list) ──────────────── */
static void *refresh_thread(void *arg){
    while(g_running){
        sleep(2);
        if(g_logged_in && strlen(g_tok)>0){
            send_pkt(PKT_LIST_USERS,g_user,"",0,"",g_tok,"");
            send_pkt(PKT_LIST_ROOMS,g_user,"",0,"",g_tok,"");
        }
    }
    return NULL;
}

/* ── receive thread ───────────────────────────────────────── */
static void *recv_thread(void *arg){
    char buf[MAX_MSG_LEN*2]; int pos=0;
    while(g_running){
        int n=recv(g_fd,buf+pos,sizeof(buf)-pos-1,0);
        if(n<=0){printf("\n[!] Server disconnected\n");g_running=0;break;}
        pos+=n; buf[pos]='\0';
        char *nl;
        while((nl=strchr(buf,'\n'))!=NULL){
            *nl='\0';
            char line[MAX_MSG_LEN*2]; strcpy(line,buf);
            int rem=pos-(nl-buf+1);
            memmove(buf,nl+1,rem); pos=rem; buf[pos]='\0';
            if(!strlen(line)) continue;

            int type=0; char from[64]="",to[64]="",content[MAX_MSG_LEN]="",tok[65]="",extra[64]="";
            jgeti(line,"type",&type);
            jget(line,"from",from,sizeof(from));
            jget(line,"to",to,sizeof(to));
            jget(line,"content",content,sizeof(content));
            jget(line,"token",tok,sizeof(tok));
            jget(line,"extra",extra,sizeof(extra));

            if(type==PKT_OK){
                if(strcmp(content,"logged_in")==0){
                    strcpy(g_tok,tok);
                    g_logged_in=1;
                    send_pkt(PKT_LIST_USERS,g_user,"",0,"",g_tok,"");

                    printf("\033[32m[✓] Đăng nhập thành công! Token: %.8s...\033[0m\n",tok);
                } else if(strcmp(content,"registered")==0){
                    printf("\033[32m[✓] Đăng ký thành công!\033[0m\n");
                } else if(strcmp(extra,"users")==0){
                    if(g_manual_user_request) {
                        printf("\033[36m[Users online]: %s\033[0m\n",content);
                        g_manual_user_request=0;
                    }
                } else if(strcmp(extra,"rooms")==0){
                    if(g_manual_user_request) {
                        printf("\033[36m[Rooms]: %s\033[0m\n",content);
                        g_manual_user_request=0;
                    }
                } else {
                    printf("\033[32m[OK] %s\033[0m\n",content);
                }
            } else if(type==PKT_RECV_MSG){
                char plain[MAX_MSG_LEN]; do_dec(content,plain);
                int tt2=0; jgeti(line,"target_type",&tt2);
                if(tt2==TARGET_ROOM)
                    printf("\033[35m[%s] %s: %s\033[0m\n",to,from,plain);
                else
                    printf("\033[33m[DM from %s]: %s\033[0m\n",from,plain);
                printf("\033[90m  └── encrypted: %s\033[0m\n",content);
            } else if(type==PKT_ERROR){
                printf("\033[31m[ERR] %s\033[0m\n",content);
            }
        }
    }
    return NULL;
}

/* ── password input (no echo) ─────────────────────────────── */
static void get_password(const char *prompt, char *buf, int n){
    struct termios t,told;
    tcgetattr(STDIN_FILENO,&told); t=told;
    t.c_lflag &= ~(ECHO); tcsetattr(STDIN_FILENO,TCSANOW,&t);
    printf("%s",prompt); fflush(stdout);
    fgets(buf,n,stdin); buf[strcspn(buf,"\n")]='\0';
    printf("\n");
    tcsetattr(STDIN_FILENO,TCSANOW,&told);
}

/* ── help ─────────────────────────────────────────────────── */
static void print_help(){
    printf("\033[36m┌─────────────────────────────────────────┐\n");
    printf("│           CryptoChat Terminal           │\n");
    printf("├─────────────────────────────────────────┤\n");
    printf("│ /register <user>   - Đăng ký tài khoản  │\n");
    printf("│ /login <user>      - Đăng nhập           │\n");
    printf("│ /dm <user>         - Nhắn tin riêng      │\n");
    printf("│ /room <room>       - Chọn nhóm chat      │\n");
    printf("│ /create <room>     - Tạo nhóm mới        │\n");
    printf("│ /join <room>       - Vào nhóm            │\n");
    printf("│ /leave             - Rời nhóm hiện tại   │\n");
    printf("│ /users             - Danh sách online    │\n");
    printf("│ /rooms             - Danh sách nhóm      │\n");
    printf("│ /help              - Hiển thị trợ giúp   │\n");
    printf("│ /quit              - Thoát               │\n");
    printf("│ <text>             - Gửi tin nhắn        │\n");
    printf("└─────────────────────────────────────────┘\033[0m\n");
}

/* ── main ─────────────────────────────────────────────────── */
int main(int argc, char **argv){
    const char *host = argc>1 ? argv[1] : "127.0.0.1";
    int         port = argc>2 ? atoi(argv[2]) : SERVER_PORT;

    /* try kernel driver */
    g_drv=crypto_open();
    printf("[Crypto] %s\n", g_drv>=0?"Kernel driver loaded":"Using fallback (pure-C)");

    /* connect */
    g_fd=socket(AF_INET,SOCK_STREAM,0);
    struct sockaddr_in srv={.sin_family=AF_INET,.sin_port=htons(port)};
    inet_pton(AF_INET,host,&srv.sin_addr);
    if(connect(g_fd,(struct sockaddr*)&srv,sizeof(srv))<0){
        perror("connect"); return 1;
    }
    printf("\033[32m[✓] Connected to %s:%d\033[0m\n",host,port);

    pthread_t t; pthread_create(&t,NULL,recv_thread,NULL); pthread_detach(t);
    pthread_t rt; pthread_create(&rt,NULL,refresh_thread,NULL); pthread_detach(rt);

    print_help();
    printf("\n");

    char line[MAX_MSG_LEN];
    while(g_running){
        if(!strlen(g_active_to))
            printf("\033[90m[no target] > \033[0m");
        else
            printf("\033[90m[→%s] > \033[0m",g_active_to);
        fflush(stdout);

        if(!fgets(line,sizeof(line),stdin)) break;
        line[strcspn(line,"\n")]='\0';
        if(!strlen(line)) continue;

        if(line[0]!='/'){
            /* send message */
            if(!strlen(g_active_to)){printf("[!] Chọn người nhận trước: /dm <user> hoặc /room <room>\n");continue;}
            char cipher[MAX_MSG_LEN]; do_enc(line,cipher);
            send_pkt(PKT_SEND_MSG,g_user,g_active_to,g_active_ttype,cipher,g_tok,"");
            printf("\033[90m  └── sent encrypted: %s\033[0m\n",cipher);
            continue;
        }

        /* commands */
        char cmd[64],arg[MAX_NAME_LEN]="";
        sscanf(line,"/%63s %127s",cmd,arg);

        if(!strcmp(cmd,"quit")){g_running=0;g_logged_in=0;break;}
        else if(!strcmp(cmd,"help")){print_help();}
        else if(!strcmp(cmd,"register")){
            if(!strlen(arg)){printf("Usage: /register <username>\n");continue;}
            char pass[MAX_PASS_LEN];
            get_password("Password: ",pass,sizeof(pass));
            strncpy(g_user,arg,MAX_NAME_LEN-1);
            send_pkt(PKT_REGISTER,arg,"",0,pass,"","");
        }
        else if(!strcmp(cmd,"login")){
            if(!strlen(arg)){printf("Usage: /login <username>\n");continue;}
            char pass[MAX_PASS_LEN];
            get_password("Password: ",pass,sizeof(pass));
            strncpy(g_user,arg,MAX_NAME_LEN-1);
            send_pkt(PKT_LOGIN,arg,"",0,pass,"","");
        }
        else if(!strcmp(cmd,"dm")){
            if(!strlen(arg)){printf("Usage: /dm <username>\n");continue;}
            strncpy(g_active_to,arg,MAX_NAME_LEN-1);
            g_active_ttype=TARGET_USER;
            printf("[→] Chat riêng với: %s\n",arg);
        }
        else if(!strcmp(cmd,"room")){
            if(!strlen(arg)){printf("Usage: /room <roomname>\n");continue;}
            strncpy(g_active_to,arg,MAX_NAME_LEN-1);
            g_active_ttype=TARGET_ROOM;
            send_pkt(PKT_JOIN_ROOM,g_user,"",0,arg,g_tok,"");
            printf("[→] Chat nhóm: %s\n",arg);
        }
        else if(!strcmp(cmd,"create")){
            if(!strlen(arg)){printf("Usage: /create <roomname>\n");continue;}
            send_pkt(PKT_CREATE_ROOM,g_user,"",0,arg,g_tok,"");
        }
        else if(!strcmp(cmd,"join")){
            if(!strlen(arg)){printf("Usage: /join <roomname>\n");continue;}
            send_pkt(PKT_JOIN_ROOM,g_user,"",0,arg,g_tok,"");
            strncpy(g_active_to,arg,MAX_NAME_LEN-1);
            g_active_ttype=TARGET_ROOM;
        }
        else if(!strcmp(cmd,"leave")){
            if(!strlen(g_active_to)||g_active_ttype!=TARGET_ROOM){printf("[!] Bạn không ở trong nhóm nào\n");continue;}
            send_pkt(PKT_LEAVE_ROOM,g_user,"",0,g_active_to,g_tok,"");
            memset(g_active_to,0,sizeof(g_active_to));
        }
        else if(!strcmp(cmd,"users")){g_manual_user_request=1;send_pkt(PKT_LIST_USERS,g_user,"",0,"",g_tok,"");}
        else if(!strcmp(cmd,"rooms")){g_manual_user_request=1;send_pkt(PKT_LIST_ROOMS,g_user,"",0,"",g_tok,"");}
        else{printf("[!] Lệnh không xác định: /%s\n",cmd);}
    }

    close(g_fd);
    if(g_drv>=0) crypto_close(g_drv);
    printf("Tạm biệt!\n");
    return 0;
}
