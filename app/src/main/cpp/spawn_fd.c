/*
 * Spawn ant while keeping the TUN file descriptor open in the child.
 *
 * Android ProcessBuilder closes all FDs except 0/1/2, so ANT_TUN_FD=<n>
 * is always EBADF in the child. We fork+exec after clearing FD_CLOEXEC
 * on the TUN fd so it is inherited at the same number.
 */

#include <errno.h>
#include <fcntl.h>
#include <jni.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>
#include <android/log.h>

#define LOG_TAG "AntSpawn"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

extern char **environ;

JNIEXPORT jint JNICALL
Java_com_ant_proxy_AntProcessManager_nativeSpawn(
        JNIEnv *env, jclass clazz,
        jstring jPath,
        jobjectArray jArgv,
        jobjectArray jEnvp,
        jint tunFd,
        jstring jLogPath) {

    (void) clazz;

    if (jPath == NULL || jArgv == NULL) {
        return -EINVAL;
    }

    const char *path = (*env)->GetStringUTFChars(env, jPath, NULL);
    if (!path) return -ENOMEM;

    const char *logPath = NULL;
    if (jLogPath != NULL) {
        logPath = (*env)->GetStringUTFChars(env, jLogPath, NULL);
    }

    jsize argc = (*env)->GetArrayLength(env, jArgv);
    char **argv = calloc((size_t) argc + 1, sizeof(char *));
    if (!argv) {
        (*env)->ReleaseStringUTFChars(env, jPath, path);
        if (logPath) (*env)->ReleaseStringUTFChars(env, jLogPath, logPath);
        return -ENOMEM;
    }
    for (jsize i = 0; i < argc; i++) {
        jstring s = (jstring) (*env)->GetObjectArrayElement(env, jArgv, i);
        const char *cs = (*env)->GetStringUTFChars(env, s, NULL);
        argv[i] = strdup(cs ? cs : "");
        (*env)->ReleaseStringUTFChars(env, s, cs);
        (*env)->DeleteLocalRef(env, s);
    }
    argv[argc] = NULL;

    char **envp = NULL;
    jsize envc = 0;
    if (jEnvp != NULL) {
        envc = (*env)->GetArrayLength(env, jEnvp);
        envp = calloc((size_t) envc + 1, sizeof(char *));
        if (!envp) {
            for (jsize i = 0; i < argc; i++) free(argv[i]);
            free(argv);
            (*env)->ReleaseStringUTFChars(env, jPath, path);
            if (logPath) (*env)->ReleaseStringUTFChars(env, jLogPath, logPath);
            return -ENOMEM;
        }
        for (jsize i = 0; i < envc; i++) {
            jstring s = (jstring) (*env)->GetObjectArrayElement(env, jEnvp, i);
            const char *cs = (*env)->GetStringUTFChars(env, s, NULL);
            envp[i] = strdup(cs ? cs : "");
            (*env)->ReleaseStringUTFChars(env, s, cs);
            (*env)->DeleteLocalRef(env, s);
        }
        envp[envc] = NULL;
    }

    if (tunFd >= 0) {
        int flags = fcntl(tunFd, F_GETFD);
        if (flags >= 0) {
            fcntl(tunFd, F_SETFD, flags & ~FD_CLOEXEC);
        }
        LOGI("spawn: keep tun_fd=%d (CLOEXEC cleared)", tunFd);
    }

    pid_t pid = fork();
    if (pid < 0) {
        int err = errno;
        LOGE("fork failed: %s", strerror(err));
        for (jsize i = 0; i < argc; i++) free(argv[i]);
        free(argv);
        if (envp) {
            for (jsize i = 0; i < envc; i++) free(envp[i]);
            free(envp);
        }
        (*env)->ReleaseStringUTFChars(env, jPath, path);
        if (logPath) (*env)->ReleaseStringUTFChars(env, jLogPath, logPath);
        return -err;
    }

    if (pid == 0) {
        if (logPath && logPath[0]) {
            int lfd = open(logPath, O_WRONLY | O_CREAT | O_APPEND, 0600);
            if (lfd >= 0) {
                dup2(lfd, STDOUT_FILENO);
                dup2(lfd, STDERR_FILENO);
                if (lfd > STDERR_FILENO) close(lfd);
            }
        }
        execve(path, argv, envp ? envp : environ);
        _exit(127);
    }

    LOGI("fork+exec ok pid=%d path=%s tun_fd=%d", (int) pid, path, tunFd);

    for (jsize i = 0; i < argc; i++) free(argv[i]);
    free(argv);
    if (envp) {
        for (jsize i = 0; i < envc; i++) free(envp[i]);
        free(envp);
    }
    (*env)->ReleaseStringUTFChars(env, jPath, path);
    if (logPath) (*env)->ReleaseStringUTFChars(env, jLogPath, logPath);

    return (jint) pid;
}

JNIEXPORT jint JNICALL
Java_com_ant_proxy_AntProcessManager_nativeKill(JNIEnv *env, jclass clazz, jint pid, jint sig) {
    (void) env;
    (void) clazz;
    if (pid <= 0) return -EINVAL;
    if (kill((pid_t) pid, sig) != 0) {
        return -errno;
    }
    return 0;
}

JNIEXPORT jint JNICALL
Java_com_ant_proxy_AntProcessManager_nativeWaitPid(JNIEnv *env, jclass clazz, jint pid, jboolean block) {
    (void) env;
    (void) clazz;
    if (pid <= 0) return -EINVAL;
    int status = 0;
    int flags = block ? 0 : WNOHANG;
    pid_t r = waitpid((pid_t) pid, &status, flags);
    if (r == 0) return 0;
    if (r < 0) return -errno;
    if (WIFEXITED(status)) return WEXITSTATUS(status);
    if (WIFSIGNALED(status)) return 128 + WTERMSIG(status);
    return status;
}
