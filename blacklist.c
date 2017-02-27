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

#define _GNU_SOURCE  // To have tdestroy declared

#include <stdlib.h>
#include <search.h>
#include "blacklist.h"


static void* ipv4_blacklist_root = NULL; 

static int ipv4_key_cmp(const void *a, const void *b)
{
     if (a == b)
         return 0;
     else if (a< b)
         return -1;
     else
         return 1; 
}

void blacklist_add_v4(struct ipv4_key * key)
{
    uint32_t addr = key->sin_addr.s_addr;
    tsearch((void *)addr, &ipv4_blacklist_root, ipv4_key_cmp); 
}

void * blacklist_find_v4(struct ipv4_key * key)
{
    uint32_t addr = key->sin_addr.s_addr;
    return tfind((void *)addr, &ipv4_blacklist_root, ipv4_key_cmp);
}

static void _blacklist_freenode(void *nodep)
{
}

#ifndef __FreeBSD__
void blacklist_reset_v4()
{
    if (ipv4_blacklist_root) {
        tdestroy(ipv4_blacklist_root, _blacklist_freenode);
        ipv4_blacklist_root = NULL;
    }
}
#endif

