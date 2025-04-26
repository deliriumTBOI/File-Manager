// file_monitor.c
// Многопоточная программа для фонового контроля изменений и целостности группы файлов

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/stat.h>
#include <time.h>
#include <signal.h>
#include <fcntl.h>
#include <errno.h>
#include <dirent.h>
#include <limits.h>
#include <syslog.h>
#include <sys/wait.h>
#include <sys/inotify.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <libgen.h>
#include <stdarg.h>

// Макросы для конфигурации
#define CONFIG_FILE         "file_monitor.conf"
#define MAX_FILES           1000
#define MAX_WATCH_DIRS      100
#define HASH_SIZE           32  // SHA256 digest length
#define BUFFER_SIZE         4096
#define MAX_LINE_LENGTH     1024
#define MAX_THREADS         16
#define DEFAULT_INTERVAL    5
#define MAX_MOVED_FILES 100
#define COOKIE_TIMEOUT 2  // секунды

// Структура для хранения информации о файле
typedef struct {
    char filepath[PATH_MAX];
    unsigned char hash[HASH_SIZE];
    time_t last_modified;
    off_t size;
    int is_changed;
    int is_monitored;
} file_info_t;

// Структура для хранения конфигурации
typedef struct {
    int check_interval;
    int thread_count;
    int use_inotify;
    int recursive_scan;
    int use_syslog;
    int log_level;
    int watch_new_files;
    char log_file[PATH_MAX];
} config_t;

typedef struct {
    char old_path[PATH_MAX];
    unsigned int cookie;
    time_t timestamp;
} moved_file_t;

// Глобальные переменные
file_info_t *files = NULL;
int file_count = 0;
int file_capacity = 0;
volatile sig_atomic_t running = 1;  
int inotify_fd = -1;
int *watch_descriptors = NULL;
int watch_count = 0;
int moved_files_count = 0;
pthread_mutex_t file_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t file_cond = PTHREAD_COND_INITIALIZER;
moved_file_t moved_files[MAX_MOVED_FILES];
config_t config;

// Функция для получения текущего времени в строковом формате
char* time_string() {
    static char buffer[64];
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", t);
    return buffer;
}

// Функция логирования
void log_message(int level, const char *format, ...) {
    va_list args;
    va_start(args, format);
    
    char buffer[1024];
    vsnprintf(buffer, sizeof(buffer), format, args);
    
    if (config.use_syslog) {
        int syslog_level = LOG_INFO;
        switch (level) {
            case 0: syslog_level = LOG_INFO; break;
            case 1: syslog_level = LOG_WARNING; break;
            case 2: syslog_level = LOG_ERR; break;
            default: syslog_level = LOG_INFO;
        }
        
        syslog(syslog_level, "%s", buffer);
    }
    
    // Вывод в консоль при соответствующем уровне
    if (level >= config.log_level) {
        const char *level_str = "INFO";
        switch (level) {
            case 0: level_str = "INFO"; break;
            case 1: level_str = "WARNING"; break;
            case 2: level_str = "ERROR"; break;
            default: level_str = "INFO";
        }
        
        printf("[%s] [%s] %s\n", time_string(), level_str, buffer);
    }
    
    // Запись в журнал, если указан файл
    if (config.log_file[0] != '\0') {
        FILE *log_file = fopen(config.log_file, "a");
        if (log_file) {
            fprintf(log_file, "[%s] [%d] %s\n", time_string(), level, buffer);
            fclose(log_file);
        }
    }
    
    va_end(args);
}

// Функция для расчета SHA-256 хеша файла с использованием современного EVP API
int calculate_hash(const char *filepath, unsigned char *hash) {
    FILE *file = fopen(filepath, "rb");
    if (!file) {
        log_message(2, "Failed to open file for hashing: %s - %s", filepath, strerror(errno));
        return -1;
    }

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        fclose(file);
        log_message(2, "Failed to create hash context for: %s", filepath);
        return -1;
    }

    if (EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) != 1) {
        EVP_MD_CTX_free(mdctx);
        fclose(file);
        log_message(2, "Failed to initialize hash algorithm for: %s", filepath);
        return -1;
    }

    unsigned char buffer[BUFFER_SIZE];
    size_t bytes;

    while ((bytes = fread(buffer, 1, BUFFER_SIZE, file)) != 0) {
        if (EVP_DigestUpdate(mdctx, buffer, bytes) != 1) {
            EVP_MD_CTX_free(mdctx);
            fclose(file);
            log_message(2, "Failed to update hash for: %s", filepath);
            return -1;
        }
    }

    unsigned int digest_len;
    if (EVP_DigestFinal_ex(mdctx, hash, &digest_len) != 1) {
        EVP_MD_CTX_free(mdctx);
        fclose(file);
        log_message(2, "Failed to finalize hash for: %s", filepath);
        return -1;
    }

    EVP_MD_CTX_free(mdctx);
    fclose(file);
    return 0;
}

// Функция для вывода хеша в строковом виде
void hash_to_string(unsigned char *hash, char *string) {
    for(int i = 0; i < HASH_SIZE; i++) {
        sprintf(&string[i*2], "%02x", hash[i]);
    }
    string[HASH_SIZE*2] = '\0';
}

// Функция для инициализации информации о файле
int init_file_info(const char *filepath, file_info_t *file_info) {
    struct stat file_stat;
    
    if (stat(filepath, &file_stat) != 0) {
        log_message(2, "Failed to get file stats: %s - %s", filepath, strerror(errno));
        return -1;
    }

    // Проверяем, является ли путь регулярным файлом
    if (!S_ISREG(file_stat.st_mode)) {
        return -1;
    }

    // Использовать snprintf вместо strncpy для безопасного копирования пути
    snprintf(file_info->filepath, PATH_MAX, "%s", filepath);
    file_info->last_modified = file_stat.st_mtime;
    file_info->size = file_stat.st_size;
    file_info->is_changed = 0;
    file_info->is_monitored = 1;

    if (calculate_hash(filepath, file_info->hash) != 0) {
        return -1;
    }

    return 0;
}

// Функция для проверки изменений в файле
int check_file_changes(file_info_t *file_info) {
    struct stat file_stat;
    
    if (stat(file_info->filepath, &file_stat) != 0) {
        log_message(1, "Failed to get file stats: %s - %s", file_info->filepath, strerror(errno));
        return -1;
    }

    // Если время модификации или размер файла изменились
    if (file_stat.st_mtime != file_info->last_modified || 
        file_stat.st_size != file_info->size) {
        
        unsigned char new_hash[HASH_SIZE];
        if (calculate_hash(file_info->filepath, new_hash) != 0) {
            return -1;
        }

        // Сравниваем хеши
        if (memcmp(file_info->hash, new_hash, HASH_SIZE) != 0) {
            char old_hash_str[HASH_SIZE*2+1];
            char new_hash_str[HASH_SIZE*2+1];
            
            hash_to_string(file_info->hash, old_hash_str);
            hash_to_string(new_hash, new_hash_str);
            
            log_message(1, "Файл изменен: %s", file_info->filepath);
            log_message(0, "  Старый хеш: %s", old_hash_str);
            log_message(0, "  Новый хеш: %s", new_hash_str);
            
            // Обновляем информацию fо файле
            memcpy(file_info->hash, new_hash, HASH_SIZE);
            file_info->last_modified = file_stat.st_mtime;
            file_info->size = file_stat.st_size;
            file_info->is_changed = 1;
            
            return 1; // Файл изменен
        }
    }
    
    return 0; // Файл не изменен
}

// Функция для добавления файла в список отслеживаемых
int add_file(const char *filepath) {
    // Проверяем, есть ли уже такой файл в списке
    for (int i = 0; i < file_count; i++) {
        if (strcmp(files[i].filepath, filepath) == 0) {
            return 0; // Файл уже добавлен
        }
    }

    // Если недостаточно места, увеличиваем емкость массива
    if (file_count >= file_capacity) {
        int new_capacity = file_capacity == 0 ? MAX_FILES : file_capacity * 2;
        file_info_t *new_files = realloc(files, new_capacity * sizeof(file_info_t));
        if (!new_files) {
            log_message(2, "Failed to allocate memory for file list");
            return -1;
        }
        files = new_files;
        file_capacity = new_capacity;
    }

    // Инициализируем информацию о файле
    if (init_file_info(filepath, &files[file_count]) == 0) {
        log_message(0, "Добавлен файл для мониторинга: %s", filepath);
        file_count++;
        return 0;
    }
    
    return -1;
}

// Рекурсивное сканирование директории
void scan_directory(const char *dirpath) {
    DIR *dir;
    struct dirent *entry;
    char filepath[PATH_MAX];
    
    if ((dir = opendir(dirpath)) == NULL) {
        log_message(2, "Failed to open directory: %s - %s", dirpath, strerror(errno));
        return;
    }
    
    while ((entry = readdir(dir)) != NULL) {
        // Пропускаем . и ..
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        snprintf(filepath, PATH_MAX, "%s/%s", dirpath, entry->d_name);
        
        struct stat file_stat;
        if (stat(filepath, &file_stat) != 0) {
            log_message(2, "Failed to get file stats: %s - %s", filepath, strerror(errno));
            continue;
        }
        
        if (S_ISDIR(file_stat.st_mode) && config.recursive_scan) {
            scan_directory(filepath);
        } else if (S_ISREG(file_stat.st_mode)) {
            pthread_mutex_lock(&file_mutex);
            add_file(filepath);
            pthread_mutex_unlock(&file_mutex);
        }
    }
    
    closedir(dir);
}

// Структура для хранения соответствия между watch descriptor и путем директории
typedef struct {
    int wd;
    char dirpath[PATH_MAX];
} watch_dir_t;

watch_dir_t *watch_dirs = NULL;

// Функция для инициализации inotify
int init_inotify(void) {
    if ((inotify_fd = inotify_init()) == -1) {
        log_message(2, "Failed to initialize inotify: %s", strerror(errno));
        return -1;
    }

    watch_descriptors = malloc(MAX_WATCH_DIRS * sizeof(int));
    if (!watch_descriptors) {
        log_message(2, "Failed to allocate memory for watch descriptors");
        close(inotify_fd);
        inotify_fd = -1;
        return -1;
    }

    watch_dirs = malloc(MAX_WATCH_DIRS * sizeof(watch_dir_t));
    if (!watch_dirs) {
        log_message(2, "Failed to allocate memory for watch directories");
        free(watch_descriptors);
        close(inotify_fd);
        inotify_fd = -1;
        return -1;
    }
    
    // Добавляем наблюдение за директориями, в которых находятся отслеживаемые файлы
    for (int i = 0; i < file_count; i++) {
        char dirpath[PATH_MAX];
        char filepath_copy[PATH_MAX];
        
        // Копируем путь к файлу, так как dirname может изменить переданную строку
        snprintf(filepath_copy, PATH_MAX, "%s", files[i].filepath);
        char *dir = dirname(filepath_copy);
        snprintf(dirpath, PATH_MAX, "%s", dir);
        
        // Проверяем, не добавлена ли уже эта директория
        int already_added = 0;
        for (int j = 0; j < watch_count; j++) {
            if (strcmp(watch_dirs[j].dirpath, dirpath) == 0) {
                already_added = 1;
                break;
            }
        }
        
        if (!already_added && watch_count < MAX_WATCH_DIRS) {
            // Базовые события для отслеживания файлов
            int mask = IN_MODIFY | IN_DELETE | IN_DELETE_SELF | IN_MOVED_FROM | IN_MOVED_TO;
            
            // Если нужно отслеживать новые файлы, добавляем соответствующие события
            if (config.watch_new_files) {
                mask |= IN_CREATE | IN_MOVED_TO;
                log_message(0, "Включен мониторинг новых файлов в директории: %s", dirpath);
            }
            
            int wd = inotify_add_watch(inotify_fd, dirpath, mask);
            if (wd == -1) {
                log_message(2, "Failed to add watch for directory: %s - %s", dirpath, strerror(errno));
            } else {
                watch_descriptors[watch_count] = wd;
                snprintf(watch_dirs[watch_count].dirpath, PATH_MAX, "%s", dirpath);
                watch_dirs[watch_count].wd = wd;
                watch_count++;
                
                if (config.watch_new_files) {
                    log_message(0, "Добавлено наблюдение за директорией с отслеживанием новых файлов: %s", dirpath);
                } else {
                    log_message(0, "Добавлено наблюдение за директорией (только текущие файлы): %s", dirpath);
                }
            }
        }
    }
    
    return 0;
}

// Функция для нахождения директории по watch descriptor
const char *find_dir_by_wd(int wd) {
    for (int i = 0; i < watch_count; i++) {
        if (watch_dirs[i].wd == wd) {
            return watch_dirs[i].dirpath;
        }
    }
    return NULL;
}

// Функция для чтения конфигурации
void read_config(const char *config_path) {
    // Значения по умолчанию
    config.check_interval = DEFAULT_INTERVAL;
    config.thread_count = 4;
    config.use_inotify = 1;
    config.recursive_scan = 1;
    config.use_syslog = 0;
    config.log_level = 0;
    config.watch_new_files = 0;
    config.log_file[0] = '\0';
    
    // Если файл не существует, используем значения по умолчанию
    FILE *config_file = fopen(config_path, "r");
    if (!config_file) {
        return;
    }
    
    char line[MAX_LINE_LENGTH];
    while (fgets(line, sizeof(line), config_file)) {
        // Удаляем символ новой строки
        char *nl = strchr(line, '\n');
        if (nl) *nl = '\0';
        
        // Пропускаем комментарии и пустые строки
        if (line[0] == '#' || line[0] == '\0') {
            continue;
        }
        
        char *key = strtok(line, "=");
        char *value = strtok(NULL, "=");
        
        if (key && value) {
            // Удаляем пробелы
            while (*key == ' ') key++;
            char *end = key + strlen(key) - 1;
            while (end > key && *end == ' ') *end-- = '\0';
            
            while (*value == ' ') value++;
            end = value + strlen(value) - 1;
            while (end > value && *end == ' ') *end-- = '\0';
            
            if (strcmp(key, "check_interval") == 0) {
                config.check_interval = atoi(value);
                if (config.check_interval < 1) config.check_interval = 1;
            } else if (strcmp(key, "thread_count") == 0) {
                config.thread_count = atoi(value);
                if (config.thread_count < 1) config.thread_count = 1;
                if (config.thread_count > MAX_THREADS) config.thread_count = MAX_THREADS;
            } else if (strcmp(key, "use_inotify") == 0) {
                config.use_inotify = atoi(value);
            } else if (strcmp(key, "recursive_scan") == 0) {
                config.recursive_scan = atoi(value);
            } else if (strcmp(key, "use_syslog") == 0) {
                config.use_syslog = atoi(value);
            } else if (strcmp(key, "log_level") == 0) {
                config.log_level = atoi(value);
            } else if (strcmp(key, "log_file") == 0) {
                snprintf(config.log_file, PATH_MAX, "%s", value);
            } else if (strcmp(key, "watch_new_files") == 0) {
                  config.watch_new_files = atoi(value);
            }
        }
    }
    
    fclose(config_file);
}

// Проверка существования файла и обновление списка при удалении
void check_file_existence(int index) {
    struct stat file_stat;
    if (stat(files[index].filepath, &file_stat) != 0) {
        // Файл не существует (возможно удален)
        log_message(1, "Файл не найден (возможно удален): %s - %s", 
                   files[index].filepath, strerror(errno));
        
        // Помечаем файл как не отслеживаемый
        files[index].is_monitored = 0;
        
        // Удаляем файл из списка наблюдения
        if (index < file_count - 1) {
            files[index] = files[file_count - 1];
        }
        file_count--;
    }
}

// Функция потока мониторинга с использованием inotify
void* inotify_thread(void *arg) {
    pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
    pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, NULL);
    (void)arg;  // Подавляем предупреждение о неиспользуемом параметре
    char buffer[4096] __attribute__((aligned(__alignof__(struct inotify_event))));
    time_t current_time;

    log_message(0, "Поток inotify запущен");
    
    while (running) {
        // Очищаем устаревшие записи о перемещениях
        time(&current_time);
        pthread_mutex_lock(&file_mutex);
        for (int i = 0; i < moved_files_count; i++) {
            if ((current_time - moved_files[i].timestamp) > COOKIE_TIMEOUT) {
                // Событие устарело, обрабатываем как удаление
                log_message(1, "Истекло время ожидания парного события для %s, файл считается удаленным", 
                          moved_files[i].old_path);
                
                // Ищем файл в списке мониторинга и удаляем его
                for (int j = 0; j < file_count; j++) {
                    if (strcmp(files[j].filepath, moved_files[i].old_path) == 0) {
                        log_message(1, "Файл удален из мониторинга: %s", files[j].filepath);
                        
                        // Удаляем файл из списка наблюдения
                        if (j < file_count - 1) {
                            files[j] = files[file_count - 1];
                        }
                        file_count--;
                        break;
                    }
                }
                
                // Удаляем запись о перемещении
                if (i < moved_files_count - 1) {
                    moved_files[i] = moved_files[moved_files_count - 1];
                }
                moved_files_count--;
                i--; // Корректировка индекса
            }
        }
        pthread_mutex_unlock(&file_mutex);
        
        // Читаем события inotify
        ssize_t len = read(inotify_fd, buffer, sizeof(buffer));
        if (len == -1) {
            if (errno == EINTR) {
                continue; // Сигнал прервал чтение
            }
            log_message(2, "Failed to read inotify events: %s", strerror(errno));
            break;
        }
        
        // Обрабатываем все события в буфере
        char *ptr = buffer;
        while (ptr < buffer + len) {
            struct inotify_event *event = (struct inotify_event *)ptr;
            
            if (event->len > 0) {
                const char *dir_path = find_dir_by_wd(event->wd);
                if (dir_path != NULL) {
                    char full_path[PATH_MAX * 2];  
                    snprintf(full_path, sizeof(full_path), "%s/%s", dir_path, event->name);
                    
                    pthread_mutex_lock(&file_mutex);
                    
                    // Обработка события IN_MOVED_FROM
                    if (event->mask & IN_MOVED_FROM) {
                        // Находим файл, который перемещается
                        int file_index = -1;
                        for (int i = 0; i < file_count; i++) {
                            char file_basename[PATH_MAX];
                            char file_copy[PATH_MAX];
                            snprintf(file_copy, PATH_MAX, "%s", files[i].filepath);
                            snprintf(file_basename, PATH_MAX, "%s", basename(file_copy));
                            
                            if (strcmp(file_basename, event->name) == 0) {
                                file_index = i;
                                break;
                            }
                        }
                        
                        if (file_index >= 0) {
                            // Сохраняем информацию о перемещаемом файле
                            if (moved_files_count < MAX_MOVED_FILES) {
                                snprintf(moved_files[moved_files_count].old_path, PATH_MAX, 
                                        "%s", files[file_index].filepath);
                                moved_files[moved_files_count].cookie = event->cookie;
                                moved_files[moved_files_count].timestamp = time(NULL);
                                moved_files_count++;
                                
                                log_message(0, "Файл возможно переименован: %s, ожидаем парное событие...", 
                                        files[file_index].filepath);
                            }
                        }
                    }
                    // Обработка события IN_MOVED_TO
                    else if (event->mask & IN_MOVED_TO) {
                        // Ищем соответствующее событие IN_MOVED_FROM по cookie
                        int moved_index = -1;
                        time(&current_time);
                        
                        for (int i = 0; i < moved_files_count; i++) {
                            if (moved_files[i].cookie == event->cookie && 
                                (current_time - moved_files[i].timestamp) <= COOKIE_TIMEOUT) {
                                moved_index = i;
                                break;
                            }
                        }
                        
                        if (moved_index >= 0) {
                            // Нашли соответствующее событие - это переименование
                            int found = 0;
                            for (int i = 0; i < file_count; i++) {
                                if (strcmp(files[i].filepath, moved_files[moved_index].old_path) == 0) {
                                    // Обновляем путь к файлу
                                    snprintf(files[i].filepath, sizeof(files[i].filepath), "%.*s", (int)(sizeof(files[i].filepath) - 1), full_path);
                                    // Обновляем информацию о файле
                                    if (init_file_info(full_path, &files[i]) == 0) {
                                        log_message(1, "Файл переименован: %s -> %s", 
                                                  moved_files[moved_index].old_path, full_path);
                                    }
                                    found = 1;
                                    break;
                                }
                            }
                            
                            // Удаляем информацию о перемещении
                            if (moved_index < moved_files_count - 1) {
                                moved_files[moved_index] = moved_files[moved_files_count - 1];
                            }
                            moved_files_count--;
                            
                            if (!found && config.watch_new_files) {
                                // Если файл не найден в списке мониторинга, это странно
                                // но на всякий случай добавим его, если включена соответствующая опция
                                struct stat file_stat;
                                if (stat(full_path, &file_stat) == 0 && S_ISREG(file_stat.st_mode)) {
                                    add_file(full_path);
                                    log_message(0, "Новый файл добавлен для мониторинга: %s", full_path);
                                }
                            }
                            
                            // Сигнал об изменении для обновления состояния
                            pthread_cond_signal(&file_cond);
                        }
                        else {
                            // Не нашли соответствующее событие - обрабатываем как новый файл
                            if (config.watch_new_files) {
                                struct stat file_stat;
                                if (stat(full_path, &file_stat) == 0 && S_ISREG(file_stat.st_mode)) {
                                    add_file(full_path);
                                    log_message(0, "Новый файл добавлен для мониторинга: %s", full_path);
                                    pthread_cond_signal(&file_cond);
                                }
                            }
                        }
                    }
                    // Проверяем, есть ли такой файл в нашем списке мониторинга
                    else {
                        int is_monitored_file = 0;
                        for (int i = 0; i < file_count; i++) {
                            if (strcmp(files[i].filepath, full_path) == 0) {
                                is_monitored_file = 1;
                                break;
                            }
                        }
                        
                        // Обработка разных событий для отслеживаемых файлов
                        if (is_monitored_file || event->mask & (IN_DELETE | IN_DELETE_SELF)) {
                            // Проверяем, есть ли такой файл в нашем списке
                            for (int i = 0; i < file_count; i++) {
                                char file_basename[PATH_MAX];
                                char file_copy[PATH_MAX];
                                snprintf(file_copy, PATH_MAX, "%s", files[i].filepath);
                                snprintf(file_basename, PATH_MAX, "%s", basename(file_copy));
                                
                                if (strcmp(file_basename, event->name) == 0) {
                                    if (event->mask & (IN_DELETE | IN_DELETE_SELF)) {
                                        log_message(1, "Файл удален: %s", files[i].filepath);
                                        
                                        // Удаляем файл из списка наблюдения
                                        if (i < file_count - 1) {
                                            files[i] = files[file_count - 1];
                                        }
                                        file_count--;
                                        i--; // Корректировка индекса
                                        
                                        // Сигнализируем об изменении
                                        pthread_cond_signal(&file_cond);
                                    } 
                                    else if (event->mask & IN_MODIFY) {
                                        // Проверяем изменения в файле
                                        if (check_file_changes(&files[i]) > 0) {
                                            // Сигнализируем об изменении
                                            pthread_cond_signal(&file_cond);
                                        }
                                    }
                                }
                            }
                        }
                        // Опционально: обработка новых файлов если в конфигурации указано
                        else if ((event->mask & IN_CREATE) && config.watch_new_files) {
                            struct stat file_stat;
                            if (stat(full_path, &file_stat) == 0 && S_ISREG(file_stat.st_mode)) {
                                add_file(full_path);
                                log_message(0, "Новый файл добавлен для мониторинга: %s", full_path);
                                pthread_cond_signal(&file_cond);
                            }
                        }
                    }
                    
                    pthread_mutex_unlock(&file_mutex);
                }
            }
            
            ptr += sizeof(struct inotify_event) + event->len;
        }
    }
    
    log_message(0, "Поток inotify завершен");
    return NULL;
}

// Функция потока мониторинга с использованием периодического опроса
void* monitor_thread(void *arg) {
    pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
    pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, NULL);
    int thread_id = *((int*)arg);
    free(arg);
    
    log_message(0, "Поток мониторинга #%d запущен", thread_id);
    
    while (running) {
        pthread_mutex_lock(&file_mutex);
        for (int i = thread_id; i < file_count; i += config.thread_count) {
            if (files[i].is_monitored) {
                // Проверяем, существует ли файл
                struct stat file_stat;
                if (stat(files[i].filepath, &file_stat) != 0) {
                    // Файл не существует (возможно удален)
                    log_message(1, "Файл не найден (возможно удален): %s - %s", 
                              files[i].filepath, strerror(errno));
                    
                    // Удаляем файл из списка наблюдения
                    if (i < file_count - 1) {
                        files[i] = files[file_count - 1];
                    }
                    file_count--;
                    i--; // Корректировка индекса
                    
                    // Сигнализируем об изменении
                    pthread_cond_signal(&file_cond);
                }
                else if (check_file_changes(&files[i]) > 0) {
                    // Файл изменен, сигнализируем об изменении
                    pthread_cond_signal(&file_cond);
                }
            }
        }
        pthread_mutex_unlock(&file_mutex);
        
        // Пауза между проверками
        sleep(config.check_interval);
    }
    
    log_message(0, "Поток мониторинга #%d завершен", thread_id);
    return NULL;
}

// Обработчик сигналов для завершения программы
void handle_signal(int sig) {
    log_message(0, "Получен сигнал завершения (%d)", sig);
    running = 0;
    
    // Разбудить все потоки, ожидающие условных переменных
    pthread_cond_broadcast(&file_cond);
    
    // Закрыть inotify, если он используется
    if (inotify_fd != -1) {
        close(inotify_fd);
    }
}

// Функция очистки ресурсов
void cleanup(void) {
    // Освобождаем память, выделенную для файлов
    if (files) {
        free(files);
        files = NULL;
    }
    
    // Освобождаем память, выделенную для watch descriptors
    if (watch_descriptors) {
        free(watch_descriptors);
        watch_descriptors = NULL;
    }

    // Освобождаем память для структуры watch_dirs
    if (watch_dirs) {
        free(watch_dirs);
        watch_dirs = NULL;
    }
   
    // Закрываем файловый дескриптор inotify, если он открыт
    if (inotify_fd != -1) {
        close(inotify_fd);
        inotify_fd = -1;
    }
    
    // Уничтожаем мьютекс и условную переменную
    pthread_mutex_destroy(&file_mutex);
    pthread_cond_destroy(&file_cond);
    
    // Закрываем syslog, если он используется
    if (config.use_syslog) {
        closelog();
    }
    
    // Очистка ресурсов OpenSSL
    OPENSSL_cleanup();
}

// Основная функция
int main(int argc, char *argv[]) {
    int opt;
    char config_path[PATH_MAX] = CONFIG_FILE;
    
    // Обработка опций командной строки
    while ((opt = getopt(argc, argv, "c:i:t:h")) != -1) {
        switch (opt) {
            case 'c':
                snprintf(config_path, PATH_MAX, "%s", optarg);
                break;
            case 'i':
                // Интервал проверки (будет переопределен из конфигурационного файла)
                break;
            case 't':
                // Количество потоков (будет переопределено из конфигурационного файла)
                break;
            case 'h':
                printf("Использование: %s [-c config_file] [-i interval] [-t threads] [-h] [file/dir ...]\n", argv[0]);
                printf("  -c config_file: путь к файлу конфигурации (по умолчанию: %s)\n", CONFIG_FILE);
                printf("  -i interval: интервал проверки в секундах (по умолчанию: %d)\n", DEFAULT_INTERVAL);
                printf("  -t threads: количество потоков (по умолчанию: 4)\n");
                printf("  -h: вывод этой справки\n");
                return 0;
            default:
                fprintf(stderr, "Неизвестная опция: %c\n", opt);
                return 1;
        }
    }
    
    // Инициализация OpenSSL
    OpenSSL_add_all_digests();
    
    // Чтение конфигурации
    read_config(config_path);
    
    // Инициализация syslog, если требуется
    if (config.use_syslog) {
        openlog("file_monitor", LOG_PID, LOG_DAEMON);
    }
    
    // Установка обработчиков сигналов
    struct sigaction sa;
    sa.sa_handler = handle_signal;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    
    // Инициализация массива файлов
    files = malloc(MAX_FILES * sizeof(file_info_t));
    if (!files) {
        log_message(2, "Failed to allocate memory for file list");
        return 1;
    }
    file_capacity = MAX_FILES;
    
    // Обработка аргументов - это могут быть файлы или директории
    for (int i = optind; i < argc; i++) {
        struct stat file_stat;
        if (stat(argv[i], &file_stat) != 0) {
            log_message(2, "Failed to get stats: %s - %s", argv[i], strerror(errno));
            continue;
        }
        
        if (S_ISDIR(file_stat.st_mode)) {
            // Если это директория, сканируем её
            scan_directory(argv[i]);
        } else if (S_ISREG(file_stat.st_mode)) {
            // Если это файл, добавляем его
            pthread_mutex_lock(&file_mutex);
            add_file(argv[i]);
            pthread_mutex_unlock(&file_mutex);
        }
    }
    
    // Проверяем, есть ли файлы для мониторинга
    if (file_count == 0) {
        log_message(2, "No files to monitor");
        cleanup();
        return 1;
    }
    
    log_message(0, "Запущен мониторинг %d файлов", file_count);
    
    // Инициализация inotify, если требуется
    if (config.use_inotify) {
        if (init_inotify() != 0) {
            log_message(1, "Failed to initialize inotify, falling back to polling");
            config.use_inotify = 0;
        }
    }
    
    // Запуск потоков мониторинга
    pthread_t *threads = malloc(config.thread_count * sizeof(pthread_t));
    if (!threads) {
        log_message(2, "Failed to allocate memory for threads");
        cleanup();
        return 1;
    }
    
    for (int i = 0; i < config.thread_count; i++) {
        int *thread_id = malloc(sizeof(int));
        if (!thread_id) {
            log_message(2, "Failed to allocate memory for thread ID");
            continue;
        }
        *thread_id = i;
        
        if (pthread_create(&threads[i], NULL, monitor_thread, thread_id) != 0) {
            log_message(2, "Failed to create monitor thread #%d", i);
            free(thread_id);
        }
    }
    
    // Запуск потока inotify, если требуется
    pthread_t inotify_thread_id;
    if (config.use_inotify) {
        if (pthread_create(&inotify_thread_id, NULL, inotify_thread, NULL) != 0) {
            log_message(2, "Failed to create inotify thread");
        }
    }

    // Ожидаем сигнала завершения (SIGINT или SIGTERM)
    while (running) {
        sleep(1);
    }
    
    for (int i = 0; i < config.thread_count; i++) {
        pthread_cancel(threads[i]); // Отменяем поток
    }

    if (config.use_inotify) {
        pthread_cancel(inotify_thread_id);
    }

    // Ожидание завершения потоков
    for (int i = 0; i < config.thread_count; i++) {
        pthread_join(threads[i], NULL);
    }
    
    if (config.use_inotify) {
        pthread_join(inotify_thread_id, NULL);
    }
    
    free(threads);
    
    log_message(0, "Программа завершена");
    
    // Очистка ресурсов
    cleanup();
    
    return 0;
}
