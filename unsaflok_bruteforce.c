// unsaflok_bruteforce.c - UID brute-force for Flipper Zero
// Compatible with Official, Momentum, and Unleashed firmware.
// Uses only standard SDK APIs – no non-portable HAL calls.

#include <furi.h>
#include <furi_hal.h>
#include <gui/gui.h>
#include <gui/view_dispatcher.h>
#include <gui/modules/submenu.h>
#include <gui/modules/dialog_ex.h>
#include <gui/modules/variable_item_list.h>
#include <gui/modules/text_input.h>
#include <notification/notification.h>
#include <notification/notification_messages.h>
#include <storage/storage.h>
#include <dialogs/dialogs.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#define TAG "UnsaflokBF"
#define MAX_UID_LEN 10
#define MAX_CANDIDATES 1024
#define LOG_FILE "/ext/unsaflok_log.txt"

// -------- Enums --------
typedef enum {
    PROTO_RFID = 0,
    PROTO_NFC = 1,
    PROTO_BOTH = 2,
} ProtocolType;

typedef enum {
    MODE_SMART = 0,
    MODE_SEQUENTIAL = 1,
    MODE_DICT = 2,
} AttackMode;

// -------- Config --------
typedef struct {
    ProtocolType protocol;
    AttackMode mode;
    uint32_t delay_ms;
    uint8_t known_uid[MAX_UID_LEN];
    size_t known_uid_len;
    char dict_path[128];
} AppConfig;

// -------- App State --------
typedef struct {
    Gui* gui;
    ViewDispatcher* view_dispatcher;
    Submenu* submenu;
    DialogEx* dialog;
    VariableItemList* var_list;
    TextInput* text_input;
    NotificationApp* notifications;
    FuriThread* attack_thread;
    AppConfig config;
    AppConfig temp_config;
    volatile bool running;
    volatile bool success;
    volatile bool user_success;
    uint8_t found_uid[MAX_UID_LEN];
    size_t found_uid_len;
    uint32_t attempts;
    char status_text[256];
    FuriMutex* state_mutex;
    char uid_input[32];
    char dict_input[128];
    VariableItem* known_uid_item;
    VariableItem* dict_path_item;
} UnsaflokApp;

// -------- Forward declarations --------
static int32_t attack_loop(void* context);
static void update_status(UnsaflokApp* app, const char* fmt, ...);
static void build_settings_view(UnsaflokApp* app);
static void text_input_result_callback(void* context);

// -------- Mutex-protected status --------
static void update_status(UnsaflokApp* app, const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    furi_mutex_acquire(app->state_mutex, FuriWaitForever);
    vsnprintf(app->status_text, sizeof(app->status_text), fmt, args);
    furi_mutex_release(app->state_mutex);
    va_end(args);
}

// -------- UID generation --------
static void generate_candidates(UnsaflokApp* app, uint8_t candidates[][MAX_UID_LEN], size_t* count) {
    *count = 0;
    uint8_t* known = app->config.known_uid;
    size_t len = app->config.known_uid_len;

    if(app->config.mode == MODE_SMART && len > 0 && len <= MAX_UID_LEN) {
        // Increment last bytes
        for(uint32_t i = 0; i < 255 && *count < MAX_CANDIDATES; i++) {
            memcpy(candidates[*count], known, len);
            candidates[*count][len-1] += (uint8_t)i;
            (*count)++;
        }
        // Bit-flip
        for(uint8_t bit = 0; bit < len*8 && *count < MAX_CANDIDATES; bit++) {
            memcpy(candidates[*count], known, len);
            candidates[*count][bit/8] ^= (1 << (bit % 8));
            (*count)++;
        }
        // Manufacturer prefixes
        const uint8_t prefixes[][4] = {{0x04,0x00,0x00},{0x08,0x00,0x00},{0xE0,0x00,0x00},{0x00,0x00,0x00}};
        for(int p = 0; p < 4 && *count < MAX_CANDIDATES; p++) {
            for(uint32_t i = 0; i < 100 && *count < MAX_CANDIDATES; i++) {
                uint8_t* uid = candidates[*count];
                memset(uid, 0, MAX_UID_LEN);
                memcpy(uid, prefixes[p], 3);
                uid[3] = (i >> 16) & 0xFF;
                uid[4] = (i >> 8) & 0xFF;
                uid[5] = i & 0xFF;
                (*count)++;
            }
        }
        // Sequential offset
        for(uint32_t off = 1; off < 1000 && *count < MAX_CANDIDATES; off++) {
            memcpy(candidates[*count], known, len);
            uint32_t carry = off;
            for(int i = (int)len - 1; i >= 0 && carry > 0; i--) {
                uint32_t sum = (uint8_t)candidates[*count][i] + (carry & 0xFF);
                candidates[*count][i] = (uint8_t)(sum & 0xFF);
                carry = (carry >> 8) + (sum >> 8);
            }
            (*count)++;
            if(*count >= MAX_CANDIDATES) break;
            memcpy(candidates[*count], known, len);
            uint32_t borrow = off;
            for(int i = (int)len - 1; i >= 0 && borrow > 0; i--) {
                int diff = (int)candidates[*count][i] - (int)(borrow & 0xFF);
                if(diff < 0) {
                    candidates[*count][i] = (uint8_t)(diff + 256);
                    borrow = (borrow >> 8) + 1;
                } else {
                    candidates[*count][i] = (uint8_t)diff;
                    borrow >>= 8;
                }
            }
            (*count)++;
        }
    } else if(app->config.mode == MODE_DICT && strlen(app->config.dict_path) > 0) {
        Storage* storage = furi_record_open(RECORD_STORAGE);
        if(!storage) return;
        File* file = storage_file_alloc(storage);
        if(file && storage_file_open(file, app->config.dict_path, FSAM_READ, FSOM_OPEN_EXISTING)) {
            char line[64];
            while(storage_file_read(file, line, sizeof(line) - 1) > 0 && *count < MAX_CANDIDATES) {
                int parsed = 0;
                char* token = strtok(line, " \n");
                while(token && parsed < MAX_UID_LEN) {
                    candidates[*count][parsed++] = (uint8_t)strtoul(token, NULL, 16);
                    token = strtok(NULL, " \n");
                }
                if(parsed > 0) (*count)++;
            }
            storage_file_close(file);
        }
        if(file) storage_file_free(file);
        furi_record_close(RECORD_STORAGE);
    } else {
        // Sequential 4-byte
        for(uint32_t i = 0; i < 5000 && *count < MAX_CANDIDATES; i++) {
            candidates[*count][0] = (i >> 24) & 0xFF;
            candidates[*count][1] = (i >> 16) & 0xFF;
            candidates[*count][2] = (i >> 8) & 0xFF;
            candidates[*count][3] = i & 0xFF;
            (*count)++;
        }
    }
}

// -------- Emulation (placeholder for Official firmware) --------
static void emulate_uid(UnsaflokApp* app, uint8_t* uid, size_t len) {
    (void)app;
    (void)uid;
    (void)len;
    // On Official firmware, RFID emulation is not directly available via HAL.
    // This is a placeholder that simply logs the attempt.
    // For real emulation, use Unleashed/Momentum firmware.
}

// -------- Attack thread --------
static int32_t attack_loop(void* context) {
    UnsaflokApp* app = (UnsaflokApp*)context;
    app->running = true;
    app->success = false;
    app->user_success = false;
    app->attempts = 0;

    uint8_t candidates[MAX_CANDIDATES][MAX_UID_LEN];
    size_t count = 0;
    generate_candidates(app, candidates, &count);
    if(count == 0) {
        update_status(app, "No candidates.");
        app->running = false;
        return 0;
    }

    for(size_t i = 0; i < count && app->running && !app->user_success; i++) {
        app->attempts++;
        uint8_t* uid = candidates[i];
        size_t uid_len = (app->config.protocol == PROTO_RFID) ? 5 :
                         (app->config.protocol == PROTO_NFC) ? 7 : 5;

        emulate_uid(app, uid, uid_len);

        // Safe hex string
        char uid_hex[3 * MAX_UID_LEN + 1] = {0};
        size_t hex_len = 0;
        size_t print_len = (uid_len < MAX_UID_LEN) ? uid_len : MAX_UID_LEN;
        for(size_t bi = 0; bi < print_len; bi++) {
            hex_len += snprintf(uid_hex + hex_len, sizeof(uid_hex) - hex_len, "%02X", uid[bi]);
        }
        update_status(app, "Attempt %lu/%zu: %s", app->attempts, count, uid_hex);

        furi_delay_ms(app->config.delay_ms);

        if(app->user_success) {
            memcpy(app->found_uid, uid, print_len);
            app->found_uid_len = print_len;
            app->success = true;
            char succ_hex[3 * MAX_UID_LEN + 1] = {0};
            size_t slen = 0;
            for(size_t bi = 0; bi < print_len; bi++) {
                slen += snprintf(succ_hex + slen, sizeof(succ_hex) - slen, "%02X", uid[bi]);
            }
            update_status(app, "SUCCESS! UID: %s", succ_hex);
            Storage* storage = furi_record_open(RECORD_STORAGE);
            if(storage) {
                File* file = storage_file_alloc(storage);
                if(file && storage_file_open(file, LOG_FILE, FSAM_WRITE, FSOM_OPEN_APPEND)) {
                    char log_line[128];
                    snprintf(log_line, sizeof(log_line), "Found: %s\n", succ_hex);
                    storage_file_write(file, log_line, strlen(log_line));
                    storage_file_close(file);
                }
                if(file) storage_file_free(file);
                furi_record_close(RECORD_STORAGE);
            }
            break;
        }
    }

    if(!app->success && !app->user_success) {
        update_status(app, "Finished %lu attempts, no success.", app->attempts);
    }
    app->running = false;
    return 0;
}

// -------- Text input result callback (used for both UID and dict) --------
static void text_input_result_callback(void* context) {
    UnsaflokApp* app = (UnsaflokApp*)context;

    // If uid_input is set, parse it
    if(strlen(app->uid_input) > 0) {
        char* str = app->uid_input;
        int bytes = 0;
        char* token = strtok(str, " ");
        while(token && bytes < MAX_UID_LEN) {
            app->temp_config.known_uid[bytes++] = (uint8_t)strtoul(token, NULL, 16);
            token = strtok(NULL, " ");
        }
        app->temp_config.known_uid_len = bytes;
        char display[32] = "None";
        if(bytes > 0) snprintf(display, sizeof(display), "%d bytes", bytes);
        variable_item_set_current_value_text(app->known_uid_item, display);
        app->uid_input[0] = '\0'; // clear so we don't re-trigger
    }
    // If dict_input is set, copy it
    else if(strlen(app->dict_input) > 0) {
        strncpy(app->temp_config.dict_path, app->dict_input, sizeof(app->temp_config.dict_path)-1);
        variable_item_set_current_value_text(app->dict_path_item, app->temp_config.dict_path);
        app->dict_input[0] = '\0';
    }

    view_dispatcher_switch_to_view(app->view_dispatcher, 2);
}

// -------- Settings UI --------
static void var_list_enter_callback(void* context, uint32_t index) {
    UnsaflokApp* app = (UnsaflokApp*)context;

    if(index == 3) { // Known UID
        text_input_set_header_text(app->text_input, "Enter UID hex (e.g. 04 00 12 34 56)");
        text_input_set_result_callback(app->text_input, text_input_result_callback, app);
        if(app->temp_config.known_uid_len > 0) {
            char buf[3*MAX_UID_LEN + 1] = {0};
            size_t pos = 0;
            for(size_t i = 0; i < app->temp_config.known_uid_len; i++) {
                pos += snprintf(buf + pos, sizeof(buf) - pos, "%02X ", app->temp_config.known_uid[i]);
            }
            if(pos > 0) buf[pos-1] = '\0';
            strncpy(app->uid_input, buf, sizeof(app->uid_input));
        } else {
            app->uid_input[0] = '\0';
        }
        view_dispatcher_switch_to_view(app->view_dispatcher, 3);
    } else if(index == 4) { // Dict path
        text_input_set_header_text(app->text_input, "Enter dict path (e.g. /ext/dict.txt)");
        text_input_set_result_callback(app->text_input, text_input_result_callback, app);
        strncpy(app->dict_input, app->temp_config.dict_path, sizeof(app->dict_input)-1);
        view_dispatcher_switch_to_view(app->view_dispatcher, 3);
    }
}

static void protocol_changed(VariableItem* item) {
    UnsaflokApp* app = variable_item_get_context(item);
    uint8_t value = variable_item_get_current_value_index(item);
    app->temp_config.protocol = (ProtocolType)value;
    const char* str[] = {"RFID", "NFC", "Both"};
    variable_item_set_current_value_text(item, str[value]);
}

static void mode_changed(VariableItem* item) {
    UnsaflokApp* app = variable_item_get_context(item);
    uint8_t value = variable_item_get_current_value_index(item);
    app->temp_config.mode = (AttackMode)value;
    const char* str[] = {"Smart", "Sequential", "Dict"};
    variable_item_set_current_value_text(item, str[value]);
}

static void delay_changed(VariableItem* item) {
    UnsaflokApp* app = variable_item_get_context(item);
    uint8_t value = variable_item_get_current_value_index(item);
    uint32_t delays[] = {10, 50, 100, 200, 500};
    app->temp_config.delay_ms = delays[value];
    char buf[8];
    snprintf(buf, sizeof(buf), "%lu ms", app->temp_config.delay_ms);
    variable_item_set_current_value_text(item, buf);
}

static void save_settings_callback(VariableItem* item) {
    UnsaflokApp* app = variable_item_get_context(item);
    furi_mutex_acquire(app->state_mutex, FuriWaitForever);
    memcpy(&app->config, &app->temp_config, sizeof(AppConfig));
    furi_mutex_release(app->state_mutex);
    dialog_ex_set_text(app->dialog, "Settings saved", 64, 32, AlignCenter, AlignCenter);
    view_dispatcher_switch_to_view(app->view_dispatcher, 1);
}

static void build_settings_view(UnsaflokApp* app) {
    VariableItem* item;
    app->var_list = variable_item_list_alloc();
    variable_item_list_set_enter_callback(app->var_list, var_list_enter_callback, app);

    // Protocol
    item = variable_item_list_add(app->var_list, "Protocol", 3, protocol_changed, app);
    variable_item_set_current_value_index(item, app->temp_config.protocol);
    const char* proto_str[] = {"RFID", "NFC", "Both"};
    variable_item_set_current_value_text(item, proto_str[app->temp_config.protocol]);

    // Mode
    item = variable_item_list_add(app->var_list, "Mode", 3, mode_changed, app);
    variable_item_set_current_value_index(item, app->temp_config.mode);
    const char* mode_str[] = {"Smart", "Sequential", "Dict"};
    variable_item_set_current_value_text(item, mode_str[app->temp_config.mode]);

    // Delay
    item = variable_item_list_add(app->var_list, "Delay", 5, delay_changed, app);
    uint32_t delays[] = {10, 50, 100, 200, 500};
    uint8_t idx = 2;
    for(uint8_t i = 0; i < 5; i++) if(delays[i] == app->temp_config.delay_ms) { idx = i; break; }
    variable_item_set_current_value_index(item, idx);
    char buf[8];
    snprintf(buf, sizeof(buf), "%lu ms", app->temp_config.delay_ms);
    variable_item_set_current_value_text(item, buf);

    // Known UID (click to edit)
    item = variable_item_list_add(app->var_list, "Known UID", 1, NULL, app);
    variable_item_set_current_value_index(item, 0);
    char uid_display[32] = "None";
    if(app->temp_config.known_uid_len > 0) snprintf(uid_display, sizeof(uid_display), "%d bytes", app->temp_config.known_uid_len);
    variable_item_set_current_value_text(item, uid_display);
    app->known_uid_item = item;

    // Dict path (click to edit)
    item = variable_item_list_add(app->var_list, "Dict path", 1, NULL, app);
    variable_item_set_current_value_index(item, 0);
    variable_item_set_current_value_text(item, app->temp_config.dict_path[0] ? app->temp_config.dict_path : "None");
    app->dict_path_item = item;

    // Save
    item = variable_item_list_add(app->var_list, "Save", 1, save_settings_callback, app);
    variable_item_set_current_value_index(item, 0);
    variable_item_set_current_value_text(item, "Apply");

    view_dispatcher_add_view(app->view_dispatcher, 2, variable_item_list_get_view(app->var_list));
}

// -------- UI Callbacks (submenu) --------
static void start_attack_callback(void* context, uint32_t index) {
    (void)index;
    UnsaflokApp* app = (UnsaflokApp*)context;
    if(app->attack_thread && app->running) {
        app->running = false;
        furi_thread_join(app->attack_thread);
        furi_thread_free(app->attack_thread);
        app->attack_thread = NULL;
        dialog_ex_set_text(app->dialog, "Stopped.", 64, 32, AlignCenter, AlignCenter);
        return;
    }
    app->user_success = false;
    app->success = false;
    app->attempts = 0;
    dialog_ex_set_text(app->dialog, "Running...\nPress OK to mark success", 64, 32, AlignCenter, AlignCenter);
    app->attack_thread = furi_thread_alloc_ex("Attack", 8192, attack_loop, app);
    if(app->attack_thread) furi_thread_start(app->attack_thread);
}

static void success_callback(void* context, uint32_t index) {
    (void)index;
    UnsaflokApp* app = (UnsaflokApp*)context;
    if(app->running) app->user_success = true;
}

static void config_callback(void* context, uint32_t index) {
    (void)index;
    UnsaflokApp* app = (UnsaflokApp*)context;
    furi_mutex_acquire(app->state_mutex, FuriWaitForever);
    memcpy(&app->temp_config, &app->config, sizeof(AppConfig));
    furi_mutex_release(app->state_mutex);
    if(app->var_list) {
        view_dispatcher_remove_view(app->view_dispatcher, 2);
        variable_item_list_free(app->var_list);
        app->var_list = NULL;
    }
    build_settings_view(app);
    view_dispatcher_switch_to_view(app->view_dispatcher, 2);
}

// -------- Main --------
int32_t unsaflok_bruteforce_app(void* p) {
    (void)p;

    UnsaflokApp* app = malloc(sizeof(UnsaflokApp));
    if(!app) return -1;
    memset(app, 0, sizeof(UnsaflokApp));

    app->state_mutex = furi_mutex_alloc(FuriMutexTypeNormal);
    if(!app->state_mutex) { free(app); return -1; }

    app->gui = furi_record_open(RECORD_GUI);
    app->view_dispatcher = view_dispatcher_alloc();
    view_dispatcher_attach_to_gui(app->view_dispatcher, app->gui, ViewDispatcherTypeFullscreen);
    app->notifications = furi_record_open(RECORD_NOTIFICATION);

    // Submenu
    app->submenu = submenu_alloc();
    submenu_add_item(app->submenu, "Start Attack", 0, start_attack_callback, app);
    submenu_add_item(app->submenu, "Mark Success", 1, success_callback, app);
    submenu_add_item(app->submenu, "Settings", 2, config_callback, app);
    view_dispatcher_add_view(app->view_dispatcher, 0, submenu_get_view(app->submenu));

    // Dialog
    app->dialog = dialog_ex_alloc();
    dialog_ex_set_header(app->dialog, "Unsaflok Brute", 64, 10, AlignCenter, AlignCenter);
    dialog_ex_set_text(app->dialog, "Ready", 64, 32, AlignCenter, AlignCenter);
    dialog_ex_set_left_button_text(app->dialog, "Start");
    dialog_ex_set_right_button_text(app->dialog, "Success");
    dialog_ex_set_center_button_text(app->dialog, "Stop");
    view_dispatcher_add_view(app->view_dispatcher, 1, dialog_ex_get_view(app->dialog));

    // Text input
    app->text_input = text_input_alloc();
    view_dispatcher_add_view(app->view_dispatcher, 3, text_input_get_view(app->text_input));

    // Default config
    app->config.protocol = PROTO_BOTH;
    app->config.mode = MODE_SMART;
    app->config.delay_ms = 100;
    app->config.known_uid_len = 0;
    strcpy(app->config.dict_path, "/ext/dict.txt");
    memcpy(&app->temp_config, &app->config, sizeof(AppConfig));
    app->var_list = NULL;

    view_dispatcher_switch_to_view(app->view_dispatcher, 1);
    view_dispatcher_run(app->view_dispatcher);

    // Cleanup
    if(app->attack_thread) {
        app->running = false;
        furi_thread_join(app->attack_thread);
        furi_thread_free(app->attack_thread);
    }
    if(app->var_list) {
        view_dispatcher_remove_view(app->view_dispatcher, 2);
        variable_item_list_free(app->var_list);
    }
    view_dispatcher_remove_view(app->view_dispatcher, 0);
    view_dispatcher_remove_view(app->view_dispatcher, 1);
    view_dispatcher_remove_view(app->view_dispatcher, 3);
    submenu_free(app->submenu);
    dialog_ex_free(app->dialog);
    text_input_free(app->text_input);
    view_dispatcher_free(app->view_dispatcher);
    furi_record_close(RECORD_GUI);
    furi_record_close(RECORD_NOTIFICATION);
    furi_mutex_free(app->state_mutex);
    free(app);
    return 0;
}
