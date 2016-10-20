/* cdns - Cure DNS
 * Copyright (C) 2016 Zhuofei Wang <semigodking@gmail.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License.  You may obtain a copy
 * of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */

#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/stat.h>
#include "cfg.h"
#include "json.h"
#include "log.h"

#define cfg_next_item(item) (item+1)

bool cfg_parse_simple_object(json_value * value, config_item * items);
static config_item * next_items_group(config_item * item);
static void * load_config_file(const char * path, size_t *len);

bool cfg_loads(const char * json, size_t len, config_item *items)
{
    bool rc = false;
    json_settings settings = { 0 };
    settings.settings = json_enable_comments;
    json_value* value = json_parse_ex(&settings, json, len, 0);
    
    if (items == NULL)
        // No config item to be processed
        return true;

    if (value == NULL)
    {
        log_error(LOG_ERR, "Failed to parse JSON content!");
        return false;
    }
    // I want root is object only
    rc = value->type == json_object;
    if (rc)
        rc = cfg_parse_simple_object(value, items);
    else
        log_error(LOG_ERR, "Only Object is accepted as JSON config root!");
    json_value_free(value);
    return rc;
}

bool cfg_loadf(const char * path, config_item * items)
{
    size_t len;
    bool rc = false;
    const char * json = (const char *)load_config_file(path, &len);
    if (json)
    {
        rc = cfg_loads(json, len, items);
        free((void *)json);
    }
    return rc;
}

static void * load_config_file(const char * path, size_t *len)
{
    FILE *fp;
    struct stat filestatus;
    size_t file_size;
    char* buff;

    if (path == NULL) {
        log_error(LOG_ERR, "Empty path specified!");
        return NULL;
    }
    if (stat(path, &filestatus) != 0) {
        log_error(LOG_ERR, "File not found: %s", path);
        return NULL;
    }
    file_size = filestatus.st_size;
    buff = (char*)malloc(filestatus.st_size);
    if (buff == NULL) {
        log_error(LOG_ERR, "Out of memory!");
        return NULL;
    }

    fp = fopen(path, "rt");
    if (fp == NULL) {
        log_error(LOG_ERR, "Unable to open file: %s\n", path);
        fclose(fp);
        free(buff);
        return NULL;
    }
    if (fread(buff, file_size, 1, fp) != 1 ) {
        log_error(LOG_ERR, "Unable t read content of %s\n", path);
        fclose(fp);
        free(buff);
        return NULL;
    }
    fclose(fp);
    *len = file_size;
    return buff;
}

/*
Release memory allocated for items. Ensure all items and subitems are ready
for next parsing.
*/
void cfg_reset_items(config_item *items)
{
    unsigned int n;
    config_item * next_items;
    if (!items)
        return;

    for (; items->key != NULL; items = cfg_next_item(items)){
        if (items->list) {
            switch (items->type) {
            case cdt_string:
                if (items->value) {
                    // Free memory for each string
                    for (; items->vcount > 0; items->vcount--)
                        free(((char **)items->value)[items->vcount -1]);
                }
                // Fall through
            case cdt_bool:
            case cdt_uint16:
            case cdt_int:
            case cdt_double:
                // Free memory for whole array
                if (items->_malloc) {
                    free(items->_malloc);
                    items->_malloc = items->value = NULL;
                }
                break;
            case cdt_object:
                // Recursively reset items in object array.
                if (items->vcount && items->subitems && items->subitems_free_cb) {
                    next_items = items->subitems;
                    for (n = 0; n < items->vcount; n++) {
                        cfg_reset_items(next_items);
                        next_items = next_items_group(next_items);
                    }
                    items->subitems_free_cb(items->subitems, items->vcount);
                    items->subitems = NULL;
                }
                items->value = NULL;
                break;
            default:
                // Should not be here
                break;
            }
        }
        else {
            switch (items->type) {
            case cdt_string:
                // Free memory allocated for string
                if (items->_malloc) {
                    free(items->_malloc);
                    items->_malloc = NULL;
                    *(char **)items->value = NULL;
                }
                break;
            case cdt_object:
                // Recursively reset subitems of object
                cfg_reset_items(items->subitems);
                break;
            default:
                 // No need to free memory
                break;
            }
        }
        items->vcount = 0;
    }
}

config_item * cfg_find_item(const char * key, config_item * items)
{
    if (key && items)
        for (; items->key != NULL; items = cfg_next_item(items))
            if (strcmp(key, items->key) == 0)
                return items;
    return NULL;
}


/* allocate memory and copy string values into destination */
static char * acopy_string(char **dst, json_value *value)
{
    char * str = malloc(value->u.string.length+1);
    if (str) {
        memcpy(str, value->u.string.ptr, value->u.string.length+1);
        *dst = str;
    }
    else {
        log_error(LOG_ERR, "Out of memory!");
    }
    return str;
}


static bool is_same_type(json_value * value, config_item * item)
{
    if (value == NULL || item == NULL)
        return false;

    return (value->type == json_boolean && item->type == cdt_bool)
        || (value->type == json_integer && item->type == cdt_uint16
            && value->u.integer >=0 && value->u.integer < 0x10000)
        || (value->type == json_integer && item->type == cdt_int)
        || (value->type == json_double && item->type == cdt_double)
        || (value->type == json_string && item->type == cdt_string)
        || (value->type == json_object && item->type == cdt_object)
        || (value->type == json_array && item->list == true);
}


static config_item * next_items_group(config_item * item)
{
    while(item && item->key) item = cfg_next_item(item);
    if (item)
        return cfg_next_item(item);
    else
        return item;
}
/*
Note: only array with items of same type is supported
*/
static bool save_list_values(json_value * value, config_item * item)
{
    int i, count;
    size_t item_size;
    config_item * next_item = NULL;
    json_value * li;
    bool rc = true;

    if (!value || !item || value->type != json_array || item->list == false)
        return false;

    count = value->u.array.length;
    if (count == 0) {
        item->vcount = count;
        return true;
    }
    
    // Special handling of objects
    if (item->type == cdt_object) {
        if (item->subitems_init_cb == NULL) {
            log_error(LOG_ERR, "Object array has no init callback associated: %s", item->key);
            return false;
        }
        next_item = item->subitems_init_cb(count);
        if (!next_item)
            return false;
        item->subitems = next_item;
        item->vcount = count;
        for (i = 0; i < count; i++) {
            if (!cfg_parse_simple_object(value->u.array.values[i], next_item)) {
                log_error(LOG_DEBUG, "Failed to handle object array: %s", next_item->key);
                // Free memory
                next_item = item->subitems;
                for (; i >= 0; i--) {
                    cfg_reset_items(next_item);
                    next_item = next_items_group(next_item);
                }
                if (item->subitems_free_cb) {
                    item->subitems_free_cb(item->subitems, count);
                }
                item->subitems = NULL;
                item->vcount = 0;
                return false;
            }
            // Move to start of next group of items
            next_item = next_items_group(next_item);
        } 
        return true;
    }
    // Calc item size
    switch (item->type) {
    case cdt_bool:
        item_size = sizeof(bool);
        break;
    case cdt_uint16:
        item_size = sizeof(uint16_t);
        break;
    case cdt_int:
        item_size = sizeof(int);
        break;
    case cdt_double:
        item_size = sizeof(double);
        break;
    case cdt_string:
        item_size = sizeof(char *);
        break;
    default:
        log_error(LOG_ERR, "Config item of type %d is not supported!", item->type);
        return false;
    }
    // Allocate memory
    item->_malloc = item->value = malloc(item_size * count);
    if (item->value == NULL) {
        log_error(LOG_ERR, "Out of memory!");
        return false;
    }
    // Store values into allocated memory
    for (i = 0; i < count && rc; i++) {
        li = value->u.array.values[i];
        rc = is_same_type(li, item);
        if (!rc)
            break;
        switch (item->type) {
        case cdt_bool:
            * ((bool *)item->value + i) = li->u.boolean;
            break;
        case cdt_uint16:
            * ((uint16_t*)item->value + i) = li->u.integer;
            break;
        case cdt_int:
            * ((int *)item->value + i) = li->u.integer;
            break;
        case cdt_double:
            * ((double *)item->value + i) = li->u.dbl;
            break;
        case cdt_string:
            if (!acopy_string((char **)item->value + i, li))
                rc = false;
            break;
        default:
            rc = false;
        }
    }
    if (!rc) {
        // Free memory allocated 
        if (item->type == cdt_string)
            for (; i >= 0; i--) {
                li = value->u.array.values[i];
                if ( * ((char **)item->value + i))
                    free(* ((char **)item->value + i));
            }
        free(item->_malloc);
        item->_malloc = item->value = NULL;
    }
    else
        item->vcount = count;
    return rc; 
}

static bool save_object_value(json_value * value, config_item * item)
{
    if (value == NULL || item == NULL) {
        log_error(LOG_DEBUG, "NULL pointers passed in!");
        return false;
    }
    if (is_same_type(value, item) == false) {
        log_error(LOG_DEBUG, "Type mismatch: %s", item->key);
        return false;
    }

    switch (value->type) {
    case json_boolean:
        if (item->value)
            *(bool *)(item->value) = value->u.boolean;
        break;
    case json_integer:
        if (item->type == cdt_uint16) {
            if (item->value)
               * (uint16_t *)(item->value) = (uint16_t)value->u.integer;
        }
        else {
            if (item->value)
               * (int *)(item->value) = (int)value->u.integer;
        }
        break;
    case json_double:
        if (item->value)
           * (double *)(item->value) = value->u.dbl;
        break;
    case json_array:
        return save_list_values(value, item);
    case json_string:
        if (item->value) {
            item->_malloc = acopy_string((char **)item->value, value);
            return item->_malloc != NULL;
         }
        break;
    case json_object:
        if (item->subitems != NULL) 
            return cfg_parse_simple_object(value, item->subitems);
        break;
    default:
        log_error(LOG_ERR, "Type %d of JSON is not supported!", value->type);
        return false;
    }
    return true;
}

bool cfg_parse_simple_object(json_value * value, config_item * items)
{
    int i, n;
    config_item * item;
    json_object_entry * obj;
   
    // accept object only
    if (value == NULL || value->type != json_object)
        return false;

    n = value->u.object.length;
    for (i = 0; i < n; i ++) {
        obj = value->u.object.values + i;
        item = cfg_find_item(obj->name, items);
        if (item) {
            if (!save_object_value(obj->value, item)) {
                // Invalid value type
                log_error(LOG_ERR, "Failed to parse attributes in: %s", item->key);
                return false;
            }
        }
        else {
            log_error(LOG_ERR, "Unrecognized attribute: %s", obj->name);
            return false;
        }
    }
    return true;
}
