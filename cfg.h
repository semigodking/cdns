#ifndef CONFIG_H_WED_AUG_13_14_38_23_2015
#define CONFIG_H_WED_AUG_13_14_38_23_2015

#include <stdlib.h>
#include <stdbool.h>

typedef enum {
    // config data type
    cdt_none = 0,
    cdt_bool,
    cdt_uint16,
    cdt_int,
    cdt_double,
    cdt_string,
    cdt_object,
} cfg_data_type;

typedef struct config_item_t {
    const char * key;
    cfg_data_type type;
    void *       value; // Must be NULL for array and object
    unsigned int vcount;
    bool         list; //
    struct config_item_t * subitems; // Must be NULL for object array
    //unsigned int n_subitems;
    // This callback is responsible for allocate and init data area for subitems.
    struct config_item_t *  (*subitems_init_cb)(unsigned int count);
    void (*subitems_free_cb)(struct config_item_t * items, unsigned int count);
    void * _malloc; // internal usage only. For remember memory allocated by configsystem.
} config_item;


bool cfg_loads(const char * json, size_t len, config_item *items);
bool cfg_loadf(const char * path, config_item * items);
void cfg_reset_items(config_item *items);
config_item * cfg_find_item(const char * key, config_item * items);

#endif /* CONFIG_H_WED_AUG_13_14_38_23_2015 */

