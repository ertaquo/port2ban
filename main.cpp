#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <list>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <errno.h>

const char * g_DefaultConfigFilename = "/etc/port2ban.conf";
const char * g_DefaultLogFilename = "/var/log/port2ban.log";
const char * g_DefaultCommand = "/sbin/iptables -I INPUT -s $IP -j DROP";

const char * g_ConfigFilename = g_DefaultConfigFilename;
const char * g_LogFilename = g_DefaultLogFilename;
const char * g_Command = g_DefaultCommand;
std::list<char *> g_aPorts;
std::list<char *> g_aWhitelist;

const size_t g_BufferSize = 1024;
char g_Buffer[1024];

FILE * g_LogFile = NULL;

void Quit() {
  if (g_ConfigFilename && g_ConfigFilename != g_DefaultConfigFilename)
    free((void *)g_ConfigFilename);
  if (g_LogFilename && g_LogFilename != g_DefaultLogFilename)
    free((void *)g_LogFilename);
  if (g_Command && g_Command != g_DefaultCommand)
    free((void *)g_Command);
  for (std::list<char *>::iterator it = g_aPorts.begin(); it != g_aPorts.end(); ++it) {
    free(*it);
  }
  for (std::list<char *>::iterator it = g_aWhitelist.begin(); it != g_aWhitelist.end(); ++it) {
    free(*it);
  }
  if (g_LogFile)
    fclose(g_LogFile);

  g_ConfigFilename = NULL;
  g_LogFilename = NULL;
  g_aPorts.clear();
  g_aWhitelist.clear();
  g_LogFile = NULL;
}

void LoadConfig() {
  FILE * f = fopen(g_ConfigFilename, "r");
  if (!f) {
    fprintf(stderr, "Cannot open config file %s\n", g_ConfigFilename);
    exit(EXIT_FAILURE);
  }

  while (char * str = fgets(g_Buffer, g_BufferSize, f)) {
    char * comment = strstr(str, ";");
    if (comment)
      *comment = '\0';
    comment = strstr(str, "#");
    if (comment)
      *comment = '\0';
    while (*str == ' ' || *str == '\t')
      str++;
    if (*str == '\0' || *str == '\n' || *str == '\r')
      continue;

    while (*str != '\0' && isspace(str[strlen(str) - 1]))
      str[strlen(str) - 1] = '\0';

    char * args = strstr(str, " ");
    if (args) {
      *args = '\0';
      args++;
    }
    char * command = str;

    if (strcmp(command, "log") == 0) {
      if (args && strcmp(args, "none") != 0) {
        g_LogFilename = strdup(args);
      } else {
        g_LogFilename = NULL;
      }
    }
    else if (strcmp(command, "command") == 0) {
      if (args) {
        g_Command = strdup(args);
      } else {
        fprintf(stderr, "Invalid command\n");
        fclose(f);
        exit(EXIT_FAILURE);
      }
    }
    else if (strcmp(command, "port") == 0 || strcmp(command, "ports") == 0 || strcmp(command, "listen") == 0) {
      if (args) {
        char * arg = strtok(args, " \t\n");
        while (arg) {
          if (strlen(arg) > 0) {
            g_aPorts.push_back(strdup(arg));
          }
          arg = strtok(NULL, " \t\n");
        }
      } else {
        fprintf(stderr, "Invalid %s\n", command);
        fclose(f);
        exit(EXIT_FAILURE);
      }
    }
    else if (strcmp(command, "whitelist") == 0) {
      if (args) {
        char * arg = strtok(args, " \t\n");
        while (arg) {
          if (strlen(arg) > 0) {
            g_aWhitelist.push_back(strdup(arg));
          }
          arg = strtok(NULL, " \t\n");
        }
      } else {
        fprintf(stderr, "Invalid %s\n", command);
        fclose(f);
        exit(EXIT_FAILURE);
      }
    }
  }

  fclose(f);
}

void DumpConfig() {
  printf("log %s\n", g_LogFilename);
  printf("command %s\n", g_Command);
  for (std::list<char *>::iterator it = g_aPorts.begin(); it != g_aPorts.end(); ++it) {
    printf("port %s\n", *it);
  }
  for (std::list<char *>::iterator it = g_aWhitelist.begin(); it != g_aWhitelist.end(); ++it) {
    printf("whitelist %s\n", *it);
  }
}

// ctrl-c ctrl-v http://blog.skahin.ru/2010/05/linux.html
char * GetTime() {
  time_t now;
  struct tm *ptr;
  static char tbuf[64];
  bzero(tbuf,64);
  time(&now);
  ptr = localtime(&now);
  strftime(tbuf,64, "%Y-%m-%e %H:%M:%S", ptr);
  return tbuf;
}

void AcceptClient(struct sockaddr_in * pSockAddrIn, struct sockaddr_in * pSockAddr, int Protocol) {
  char ip[INET_ADDRSTRLEN];
  char port[8] = {0};
  char addr[INET_ADDRSTRLEN + 8] = {0};
  char proto[8] = {0};
  char addr_with_proto[INET_ADDRSTRLEN + 16] = {0};

  inet_ntop(pSockAddr->sin_family, &pSockAddr->sin_addr, ip, INET_ADDRSTRLEN);
  sprintf(port, "%d", ntohs(pSockAddrIn->sin_port));
  sprintf(addr, "%s:%s", ip, port);
  sprintf(proto, "%s", Protocol == SOCK_DGRAM ? "udp" : "tcp");
  sprintf(addr_with_proto, "%s/%s", addr, proto);

  for (std::list<char *>::iterator it = g_aWhitelist.begin(); it != g_aWhitelist.end(); ++it) {
    if (strcmp(ip, *it) == 0 || strcmp(addr, *it) == 0 || strcmp(addr_with_proto, *it) == 0)
      return;
  }

  fprintf(g_LogFile, "%s - INFO - Block %s\n", GetTime(), addr_with_proto);
  fflush(g_LogFile);

  char cmd[65536] = {0};
  char * s = cmd;
  size_t ip_len = strlen(ip);
  size_t port_len = strlen(port);
  size_t addr_len = strlen(addr);
  size_t proto_len = strlen(proto);
  size_t addr_with_proto_len = strlen(addr_with_proto);
  size_t cmd_len = strlen(g_Command);
  for (int i = 0; i < cmd_len; i++) {
    if (i < cmd_len - 3 && memcmp(&g_Command[i], "$IP", 3) == 0) {
      memcpy(s, ip, ip_len);
      s += ip_len;
      i += 2;
    }
    else if (i < cmd_len - 5 && memcmp(&g_Command[i], "$PORT", 5) == 0) {
      memcpy(s, port, port_len);
      s += port_len;
      i += 4;
    }
    else if (i < cmd_len - 5 && memcmp(&g_Command[i], "$ADDR", 5) == 0) {
      memcpy(s, addr, addr_len);
      s += addr_len;
      i += 4;
    }
    else if (i < cmd_len - 6 && memcmp(&g_Command[i], "$PROTO", 6) == 0) {
      memcpy(s, proto, proto_len);
      s += proto_len;
      i += 5;
    }
    else if (i < cmd_len - 16 && memcmp(&g_Command[i], "$ADDR_WITH_PROTO", 16) == 0) {
      memcpy(s, addr_with_proto, addr_with_proto_len);
      s += addr_with_proto_len;
      i += 15;
    }
    else if (i < cmd_len - 16 && memcmp(&g_Command[i], "$FULL_ADDR", 10) == 0) {
      memcpy(s, addr_with_proto, addr_with_proto_len);
      s += addr_with_proto_len;
      i += 9;
    }
    else {
      *s = g_Command[i];
      s++;
    }
  }
  *s = '\0';

  int code = system(cmd);
  if (code != EXIT_SUCCESS) {
    fprintf(g_LogFile, "%s - WARNING - Error executing command (exit code = %d): %s\n", GetTime(), code, cmd);
    fflush(g_LogFile);
  }
}

void ChildServer(char * PortName) {
  char * pname = PortName;

  struct sockaddr_in sin;
  sin.sin_family = AF_INET;
  sin.sin_addr.s_addr = htonl(INADDR_ANY);

  char * arg = strchr(PortName, ':');
  if (arg) {
    *arg = '\0';
    inet_pton(sin.sin_family, PortName, &sin.sin_addr);
    *arg = ':';
    pname = arg + 1;
  }

  sin.sin_port = htons(atoi(pname));

  int proto = SOCK_STREAM;

  arg = strchr(PortName, '/');
  if (arg) {
    arg++;
    for (char * c = arg; *c; c++)
      *c = tolower(*c);
    if (strcmp(arg, "udp") == 0) {
      proto = SOCK_DGRAM;
    }
  }

  int listener = socket(AF_INET, proto, 0);

  if (bind(listener, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
    fprintf(g_LogFile, "%s - ERROR - Cannot bind socket to %s\n", GetTime(), PortName);
    fflush(g_LogFile);
    return;
  }

  struct sockaddr_in client;
  socklen_t slen = sizeof(client);

  if (proto == SOCK_STREAM) {
    if (listen(listener, 16) < 0) {
      fprintf(g_LogFile, "%s - ERROR - Cannot listen socket to %s\n", GetTime(), PortName);
      fflush(g_LogFile);
      return;
    }

    fprintf(g_LogFile, "%s - INFO - Listen for clients on %s\n", GetTime(), PortName);
    fflush(g_LogFile);
    while(true) {
      slen = sizeof(client);
      int fd = accept(listener, (struct sockaddr*)&client, &slen);
      if (fd < 0) {
        fprintf(g_LogFile, "%s - WARNING - Error accepting client on %s\n", GetTime(), PortName);
        fflush(g_LogFile);
      } else {
        AcceptClient(&sin, &client, proto);
        close(fd);
      }
    }
  } else {
    fprintf(g_LogFile, "%s - INFO - Listen for clients on %s\n", GetTime(), PortName);

    while (true) {
      slen = sizeof(client);
      recvfrom(listener, g_Buffer, g_BufferSize, 0, (struct sockaddr *)&client, &slen);
      AcceptClient(&sin, &client, proto);
    }
  }
}

void KillChildrenAndDie(int status) {
  kill(0, SIGHUP);
  exit(EXIT_SUCCESS);
}

int main(int argc, const char * argv[]) {
  if (argc%2 != 1) {
    fprintf(stderr, "Wrong arguments.\nUsage: \n\tport2ban [-c|--config <config filename>]\n");
    return EXIT_FAILURE;
  }

  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "-c") == 0 || strcmp(argv[i], "--config") == 0) {
      g_ConfigFilename = strdup(argv[i + 1]);
    }
  }

  atexit(Quit);

  LoadConfig();

  if (g_aPorts.empty()) {
    fprintf(stderr, "Ports are not specified\n");
    return EXIT_FAILURE;
  }

  g_LogFile = fopen(g_LogFilename, "a+");
  if (!g_LogFile) {
    fprintf(stderr, "Cannot open log file %s\n", g_LogFilename);
    return EXIT_FAILURE;
  }

  fprintf(g_LogFile, "%s - INFO - Starting port2ban...\n", GetTime());
  fflush(g_LogFile);

  pid_t pid, sid;
  pid = fork();
  if (pid < 0) {
    fprintf(stderr, "Cannot start daemon.\n");
    fprintf(g_LogFile, "%s - ERROR - Cannot start daemon\n", GetTime());
    fflush(g_LogFile);
    return EXIT_FAILURE;
  }
  else if (pid != 0) {
    return EXIT_SUCCESS;
  }

  umask(0);

  sid = setsid();
  if (sid < 0) {
    fprintf(stderr, "Cannot start daemon.\n");
    fprintf(g_LogFile, "%s - ERROR - Cannot start daemon\n", GetTime());
    fflush(g_LogFile);
    return EXIT_FAILURE;
  }

  close(STDIN_FILENO);
  close(STDOUT_FILENO);
  close(STDERR_FILENO);

  signal(SIGHUP, KillChildrenAndDie);
  signal(SIGTERM, KillChildrenAndDie);

  for (std::list<char *>::iterator it = g_aPorts.begin(); it != g_aPorts.end(); ++it) {
    pid = fork();
    if (pid == 0) {
      fprintf(g_LogFile, "%s - INFO - Starting for port %s\n", GetTime(), *it);
      fflush(g_LogFile);
      ChildServer(*it);
    }
    else if (pid < 0) {
      fprintf(g_LogFile, "%s - ERROR - Cannot fork for port %s\n", GetTime(), *it);
      fflush(g_LogFile);
    }
  }

  wait(NULL);

  return EXIT_SUCCESS;
}
