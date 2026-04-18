#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include "monitor_ioctl.h"

#define STACK_SIZE (1024 * 1024)
#define CONTAINER_ID_LEN 32
#define CONTROL_PATH "/tmp/mini_runtime.sock"
#define LOG_DIR "logs"
#define CONTROL_MESSAGE_LEN 256
#define CHILD_COMMAND_LEN 256
#define LOG_CHUNK_SIZE 4096
#define LOG_BUFFER_CAPACITY 16
#define DEFAULT_SOFT_LIMIT (40UL << 20)
#define DEFAULT_HARD_LIMIT (64UL << 20)

typedef enum {
    CMD_SUPERVISOR = 0, CMD_START, CMD_RUN, CMD_PS, CMD_LOGS, CMD_STOP
} command_kind_t;

typedef enum {
    CONTAINER_STARTING = 0, CONTAINER_RUNNING, CONTAINER_STOPPED, CONTAINER_KILLED, CONTAINER_EXITED
} container_state_t;

typedef struct container_record {
    char id[CONTAINER_ID_LEN];
    pid_t host_pid;
    time_t started_at;
    container_state_t state;
    unsigned long soft_limit_bytes;
    unsigned long hard_limit_bytes;
    int exit_code;
    int exit_signal;
    char log_path[PATH_MAX];
    int stop_requested;
    struct container_record *next;
} container_record_t;

typedef struct {
    char container_id[CONTAINER_ID_LEN];
    size_t length;
    char data[LOG_CHUNK_SIZE];
} log_item_t;

typedef struct {
    log_item_t items[LOG_BUFFER_CAPACITY];
    size_t head;
    size_t tail;
    size_t count;
    int shutting_down;
    pthread_mutex_t mutex;
    pthread_cond_t not_empty;
    pthread_cond_t not_full;
} bounded_buffer_t;

typedef struct {
    command_kind_t kind;
    char container_id[CONTAINER_ID_LEN];
    char rootfs[PATH_MAX];
    char command[CHILD_COMMAND_LEN];
    unsigned long soft_limit_bytes;
    unsigned long hard_limit_bytes;
    int nice_value;
} control_request_t;

typedef struct {
    int status;
    char message[CONTROL_MESSAGE_LEN];
} control_response_t;

typedef struct {
    char id[CONTAINER_ID_LEN];
    char rootfs[PATH_MAX];
    char command[CHILD_COMMAND_LEN];
    int nice_value;
    int log_write_fd;
} child_config_t;

typedef struct {
    int server_fd;
    int monitor_fd;
    int should_stop;
    pthread_t logger_thread;
    bounded_buffer_t log_buffer;
    pthread_mutex_t metadata_lock;
    container_record_t *containers;
} supervisor_ctx_t;

typedef struct {
    int pipe_fd;
    char container_id[CONTAINER_ID_LEN];
    supervisor_ctx_t *ctx;
} pipe_reader_args_t;

static supervisor_ctx_t *global_ctx = NULL;

static void usage(const char *prog) {
    fprintf(stderr,
            "Usage:\n"
            "  %s supervisor <base-rootfs>\n"
            "  %s start <id> <container-rootfs> <command> [--soft-mib N] [--hard-mib N] [--nice N]\n"
            "  %s run <id> <container-rootfs> <command> [--soft-mib N] [--hard-mib N] [--nice N]\n"
            "  %s ps\n"
            "  %s logs <id>\n"
            "  %s stop <id>\n",
            prog, prog, prog, prog, prog, prog);
}

static int parse_mib_flag(const char *flag, const char *value, unsigned long *target_bytes) {
    char *end = NULL;
    unsigned long mib;
    errno = 0;
    mib = strtoul(value, &end, 10);
    if (errno != 0 || end == value || *end != '\0') return -1;
    if (mib > ULONG_MAX / (1UL << 20)) return -1;
    *target_bytes = mib * (1UL << 20);
    return 0;
}

static int parse_optional_flags(control_request_t *req, int argc, char *argv[], int start_index) {
    for (int i = start_index; i < argc; i += 2) {
        char *end = NULL;
        long nice_value;
        if (i + 1 >= argc) return -1;
        if (strcmp(argv[i], "--soft-mib") == 0) {
            if (parse_mib_flag("--soft-mib", argv[i + 1], &req->soft_limit_bytes) != 0) return -1;
            continue;
        }
        if (strcmp(argv[i], "--hard-mib") == 0) {
            if (parse_mib_flag("--hard-mib", argv[i + 1], &req->hard_limit_bytes) != 0) return -1;
            continue;
        }
        if (strcmp(argv[i], "--nice") == 0) {
            errno = 0;
            nice_value = strtol(argv[i + 1], &end, 10);
            if (errno != 0 || end == argv[i + 1] || *end != '\0' || nice_value < -20 || nice_value > 19) return -1;
            req->nice_value = (int)nice_value;
            continue;
        }
        return -1;
    }
    if (req->soft_limit_bytes > req->hard_limit_bytes) return -1;
    return 0;
}

static const char *state_to_string(container_state_t state) {
    switch (state) {
        case CONTAINER_STARTING: return "starting";
        case CONTAINER_RUNNING: return "running";
        case CONTAINER_STOPPED: return "stopped";
        case CONTAINER_KILLED: return "killed";
        case CONTAINER_EXITED: return "exited";
        default: return "unknown";
    }
}

static int bounded_buffer_init(bounded_buffer_t *buffer) {
    memset(buffer, 0, sizeof(*buffer));
    if (pthread_mutex_init(&buffer->mutex, NULL) != 0) return -1;
    if (pthread_cond_init(&buffer->not_empty, NULL) != 0) return -1;
    if (pthread_cond_init(&buffer->not_full, NULL) != 0) return -1;
    return 0;
}

static void bounded_buffer_destroy(bounded_buffer_t *buffer) {
    pthread_cond_destroy(&buffer->not_full);
    pthread_cond_destroy(&buffer->not_empty);
    pthread_mutex_destroy(&buffer->mutex);
}

static void bounded_buffer_begin_shutdown(bounded_buffer_t *buffer) {
    pthread_mutex_lock(&buffer->mutex);
    buffer->shutting_down = 1;
    pthread_cond_broadcast(&buffer->not_empty);
    pthread_cond_broadcast(&buffer->not_full);
    pthread_mutex_unlock(&buffer->mutex);
}

int bounded_buffer_push(bounded_buffer_t *buffer, const log_item_t *item) {
    pthread_mutex_lock(&buffer->mutex);
    while (buffer->count == LOG_BUFFER_CAPACITY && !buffer->shutting_down) {
        pthread_cond_wait(&buffer->not_full, &buffer->mutex);
    }
    if (buffer->shutting_down) {
        pthread_mutex_unlock(&buffer->mutex);
        return -1;
    }
    buffer->items[buffer->tail] = *item;
    buffer->tail = (buffer->tail + 1) % LOG_BUFFER_CAPACITY;
    buffer->count++;
    pthread_cond_signal(&buffer->not_empty);
    pthread_mutex_unlock(&buffer->mutex);
    return 0;
}

int bounded_buffer_pop(bounded_buffer_t *buffer, log_item_t *item) {
    pthread_mutex_lock(&buffer->mutex);
    while (buffer->count == 0 && !buffer->shutting_down) {
        pthread_cond_wait(&buffer->not_empty, &buffer->mutex);
    }
    if (buffer->shutting_down && buffer->count == 0) {
        pthread_mutex_unlock(&buffer->mutex);
        return -1;
    }
    *item = buffer->items[buffer->head];
    buffer->head = (buffer->head + 1) % LOG_BUFFER_CAPACITY;
    buffer->count--;
    pthread_cond_signal(&buffer->not_full);
    pthread_mutex_unlock(&buffer->mutex);
    return 0;
}

void *logging_thread(void *arg) {
    supervisor_ctx_t *ctx = (supervisor_ctx_t *)arg;
    log_item_t item;
    struct stat st = {0};
    if (stat(LOG_DIR, &st) == -1) mkdir(LOG_DIR, 0700);
    
    while (bounded_buffer_pop(&ctx->log_buffer, &item) == 0) {
        char filepath[PATH_MAX];
        snprintf(filepath, PATH_MAX, "%s/%s.log", LOG_DIR, item.container_id);
        FILE *f = fopen(filepath, "a");
        if (f) {
            fwrite(item.data, 1, item.length, f);
            fclose(f);
        }
    }
    return NULL;
}

void *pipe_reader_thread(void *arg) {
    pipe_reader_args_t *args = (pipe_reader_args_t *)arg;
    char buffer[LOG_CHUNK_SIZE];
    ssize_t bytes_read;
    
    while ((bytes_read = read(args->pipe_fd, buffer, sizeof(buffer))) > 0) {
        log_item_t item;
        memset(&item, 0, sizeof(item));
        strncpy(item.container_id, args->container_id, CONTAINER_ID_LEN - 1);
        item.length = bytes_read;
        memcpy(item.data, buffer, bytes_read);
        if (bounded_buffer_push(&args->ctx->log_buffer, &item) != 0) break;
    }
    close(args->pipe_fd);
    free(args);
    return NULL;
}

int child_fn(void *arg) {
    child_config_t *config = (child_config_t *)arg;
    
    if (config->nice_value != 0) {
        nice(config->nice_value);
    }

    if (config->log_write_fd != -1) {
        dup2(config->log_write_fd, STDOUT_FILENO);
        dup2(config->log_write_fd, STDERR_FILENO);
        close(config->log_write_fd);
    }

    if (chroot(config->rootfs) != 0) return 1;
    if (chdir("/") != 0) return 1;
    if (mount("proc", "/proc", "proc", 0, NULL) != 0) return 1;

    char *cmd_args[] = {"/bin/sh", "-c", config->command, NULL};
    execvp(cmd_args[0], cmd_args);
    return 1;
}

int register_with_monitor(int monitor_fd, const char *container_id, pid_t host_pid, unsigned long soft_limit_bytes, unsigned long hard_limit_bytes) {
    struct monitor_request req;
    memset(&req, 0, sizeof(req));
    req.pid = host_pid;
    req.soft_limit_bytes = soft_limit_bytes;
    req.hard_limit_bytes = hard_limit_bytes;
    strncpy(req.container_id, container_id, sizeof(req.container_id) - 1);
    if (ioctl(monitor_fd, MONITOR_REGISTER, &req) < 0) return -1;
    return 0;
}

int unregister_from_monitor(int monitor_fd, const char *container_id, pid_t host_pid) {
    struct monitor_request req;
    memset(&req, 0, sizeof(req));
    req.pid = host_pid;
    strncpy(req.container_id, container_id, sizeof(req.container_id) - 1);
    if (ioctl(monitor_fd, MONITOR_UNREGISTER, &req) < 0) return -1;
    return 0;
}

static void sigchld_handler(int signo) {
    (void)signo;
    int status;
    pid_t pid;
    while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
        if (!global_ctx) continue;
        pthread_mutex_lock(&global_ctx->metadata_lock);
        container_record_t *curr = global_ctx->containers;
        while (curr) {
            if (curr->host_pid == pid) {
                if (WIFEXITED(status)) {
                    curr->exit_code = WEXITSTATUS(status);
                    curr->state = CONTAINER_EXITED;
                } else if (WIFSIGNALED(status)) {
                    curr->exit_signal = WTERMSIG(status);
                    if (curr->stop_requested) {
                        curr->state = CONTAINER_STOPPED;
                    } else if (curr->exit_signal == SIGKILL) {
                        curr->state = CONTAINER_KILLED;
                    } else {
                        curr->state = CONTAINER_EXITED;
                    }
                }
                if (global_ctx->monitor_fd >= 0) {
                    unregister_from_monitor(global_ctx->monitor_fd, curr->id, pid);
                }
                break;
            }
            curr = curr->next;
        }
        pthread_mutex_unlock(&global_ctx->metadata_lock);
    }
}

static int run_supervisor(const char *rootfs) {
    (void)rootfs;
    supervisor_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    global_ctx = &ctx;

    ctx.monitor_fd = open("/dev/container_monitor", O_RDWR);
    
    pthread_mutex_init(&ctx.metadata_lock, NULL);
    bounded_buffer_init(&ctx.log_buffer);
    pthread_create(&ctx.logger_thread, NULL, logging_thread, &ctx);

    struct sigaction sa;
    sa.sa_handler = sigchld_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART | SA_NOCLDSTOP;
    sigaction(SIGCHLD, &sa, NULL);

    ctx.server_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    unlink(CONTROL_PATH);
    strncpy(addr.sun_path, CONTROL_PATH, sizeof(addr.sun_path) - 1);
    bind(ctx.server_fd, (struct sockaddr *)&addr, sizeof(addr));
    listen(ctx.server_fd, 10);

    while (!ctx.should_stop) {
        int client_fd = accept(ctx.server_fd, NULL, NULL);
        if (client_fd < 0) continue;

        control_request_t req;
        control_response_t res;
        memset(&res, 0, sizeof(res));
        ssize_t r = read(client_fd, &req, sizeof(req));
        if (r <= 0) {
            close(client_fd);
            continue;
        }

        pthread_mutex_lock(&ctx.metadata_lock);
        if (req.kind == CMD_START || req.kind == CMD_RUN) {
            int pipefd[2];
            pipe(pipefd);
            
            child_config_t *cfg = malloc(sizeof(child_config_t));
            strncpy(cfg->id, req.container_id, CONTAINER_ID_LEN - 1);
            strncpy(cfg->rootfs, req.rootfs, PATH_MAX - 1);
            strncpy(cfg->command, req.command, CHILD_COMMAND_LEN - 1);
            cfg->nice_value = req.nice_value;
            cfg->log_write_fd = pipefd[1];

            char *stack = malloc(STACK_SIZE);
            pid_t pid = clone(child_fn, stack + STACK_SIZE, CLONE_NEWPID | CLONE_NEWNS | CLONE_NEWUTS | SIGCHLD, cfg);

            if (pid > 0) {
                close(pipefd[1]);
                pipe_reader_args_t *pr_args = malloc(sizeof(pipe_reader_args_t));
                pr_args->pipe_fd = pipefd[0];
                pr_args->ctx = &ctx;
                strncpy(pr_args->container_id, req.container_id, CONTAINER_ID_LEN - 1);
                
                pthread_t pr_thread;
                pthread_create(&pr_thread, NULL, pipe_reader_thread, pr_args);
                pthread_detach(pr_thread);

                container_record_t *rec = malloc(sizeof(container_record_t));
                memset(rec, 0, sizeof(container_record_t));
                strncpy(rec->id, req.container_id, CONTAINER_ID_LEN - 1);
                rec->host_pid = pid;
                rec->state = CONTAINER_RUNNING;
                rec->started_at = time(NULL);
                rec->soft_limit_bytes = req.soft_limit_bytes;
                rec->hard_limit_bytes = req.hard_limit_bytes;
                snprintf(rec->log_path, PATH_MAX, "%s/%s.log", LOG_DIR, rec->id);
                rec->next = ctx.containers;
                ctx.containers = rec;

                if (ctx.monitor_fd >= 0) {
                    register_with_monitor(ctx.monitor_fd, rec->id, pid, rec->soft_limit_bytes, rec->hard_limit_bytes);
                }
                res.status = 0;
                snprintf(res.message, CONTROL_MESSAGE_LEN, "Started %s (PID: %d)", req.container_id, pid);
            } else {
                res.status = 1;
                snprintf(res.message, CONTROL_MESSAGE_LEN, "Failed to start container");
                free(stack);
            }
        } else if (req.kind == CMD_PS) {
            char ps_buf[4096] = "ID\tPID\tSTATE\tSOFT\tHARD\n";
            container_record_t *curr = ctx.containers;
            while (curr) {
                char line[256];
                snprintf(line, sizeof(line), "%s\t%d\t%s\t%lu\t%lu\n", curr->id, curr->host_pid, state_to_string(curr->state), curr->soft_limit_bytes, curr->hard_limit_bytes);
                strncat(ps_buf, line, sizeof(ps_buf) - strlen(ps_buf) - 1);
                curr = curr->next;
            }
            strncpy(res.message, ps_buf, CONTROL_MESSAGE_LEN - 1);
            res.status = 0;
        } else if (req.kind == CMD_STOP) {
            container_record_t *curr = ctx.containers;
            int found = 0;
            while (curr) {
                if (strcmp(curr->id, req.container_id) == 0 && curr->state == CONTAINER_RUNNING) {
                    curr->stop_requested = 1;
                    kill(curr->host_pid, SIGTERM);
                    found = 1;
                    break;
                }
                curr = curr->next;
            }
            if (found) {
                snprintf(res.message, CONTROL_MESSAGE_LEN, "Stop signal sent to %s", req.container_id);
            } else {
                snprintf(res.message, CONTROL_MESSAGE_LEN, "Container not running or not found");
            }
            res.status = 0;
        }
        pthread_mutex_unlock(&ctx.metadata_lock);

        write(client_fd, &res, sizeof(res));
        close(client_fd);
    }

    bounded_buffer_begin_shutdown(&ctx.log_buffer);
    pthread_join(ctx.logger_thread, NULL);
    bounded_buffer_destroy(&ctx.log_buffer);
    
    container_record_t *curr = ctx.containers;
    while (curr) {
        container_record_t *next = curr->next;
        free(curr);
        curr = next;
    }
    pthread_mutex_destroy(&ctx.metadata_lock);
    if (ctx.monitor_fd >= 0) close(ctx.monitor_fd);
    close(ctx.server_fd);
    unlink(CONTROL_PATH);
    return 0;
}

static int send_control_request(const control_request_t *req) {
    int sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock < 0) return 1;
    
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, CONTROL_PATH, sizeof(addr.sun_path) - 1);
    
    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
        close(sock);
        return 1;
    }
    write(sock, req, sizeof(*req));
    
    control_response_t res;
    if (read(sock, &res, sizeof(res)) > 0) {
        printf("%s\n", res.message);
    }
    close(sock);
    return res.status;
}

static int cmd_start(int argc, char *argv[]) {
    control_request_t req;
    if (argc < 5) return 1;
    memset(&req, 0, sizeof(req));
    req.kind = CMD_START;
    strncpy(req.container_id, argv[2], sizeof(req.container_id) - 1);
    strncpy(req.rootfs, argv[3], sizeof(req.rootfs) - 1);
    strncpy(req.command, argv[4], sizeof(req.command) - 1);
    req.soft_limit_bytes = DEFAULT_SOFT_LIMIT;
    req.hard_limit_bytes = DEFAULT_HARD_LIMIT;
    if (parse_optional_flags(&req, argc, argv, 5) != 0) return 1;
    return send_control_request(&req);
}

static int cmd_run(int argc, char *argv[]) {
    control_request_t req;
    if (argc < 5) return 1;
    memset(&req, 0, sizeof(req));
    req.kind = CMD_RUN;
    strncpy(req.container_id, argv[2], sizeof(req.container_id) - 1);
    strncpy(req.rootfs, argv[3], sizeof(req.rootfs) - 1);
    strncpy(req.command, argv[4], sizeof(req.command) - 1);
    req.soft_limit_bytes = DEFAULT_SOFT_LIMIT;
    req.hard_limit_bytes = DEFAULT_HARD_LIMIT;
    if (parse_optional_flags(&req, argc, argv, 5) != 0) return 1;
    return send_control_request(&req);
}

static int cmd_ps(void) {
    control_request_t req;
    memset(&req, 0, sizeof(req));
    req.kind = CMD_PS;
    return send_control_request(&req);
}

static int cmd_logs(int argc, char *argv[]) {
    if (argc < 3) return 1;
    char filepath[PATH_MAX];
    snprintf(filepath, PATH_MAX, "%s/%s.log", LOG_DIR, argv[2]);
    FILE *f = fopen(filepath, "r");
    if (!f) return 1;
    char buffer[1024];
    while (fgets(buffer, sizeof(buffer), f)) {
        printf("%s", buffer);
    }
    fclose(f);
    return 0;
}

static int cmd_stop(int argc, char *argv[]) {
    control_request_t req;
    if (argc < 3) return 1;
    memset(&req, 0, sizeof(req));
    req.kind = CMD_STOP;
    strncpy(req.container_id, argv[2], sizeof(req.container_id) - 1);
    return send_control_request(&req);
}

int main(int argc, char *argv[]) {
    if (argc < 2) return 1;
    if (strcmp(argv[1], "supervisor") == 0) return run_supervisor(argc > 2 ? argv[2] : "");
    if (strcmp(argv[1], "start") == 0) return cmd_start(argc, argv);
    if (strcmp(argv[1], "run") == 0) return cmd_run(argc, argv);
    if (strcmp(argv[1], "ps") == 0) return cmd_ps();
    if (strcmp(argv[1], "logs") == 0) return cmd_logs(argc, argv);
    if (strcmp(argv[1], "stop") == 0) return cmd_stop(argc, argv);
    usage(argv[0]);
    return 1;
}
