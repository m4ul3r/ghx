/*
 * Challenge 1: inventory
 *
 * A small stock manager with a linked-list Item struct. Exercises struct
 * recovery, local retype, field-xrefs, callsites, bundle, and prototype
 * recovery.
 *
 * Build with:  gcc -O2 -fno-inline -o inventory inventory.c
 * Strip with:  strip --strip-all inventory
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

struct Item {
    int id;
    int count;
    int price_cents;
    char name[24];
    struct Item *next;
};

static struct Item *inventory_head = NULL;
static int next_item_id = 1000;

static struct Item *item_new(const char *name, int count, int price_cents) {
    struct Item *it = calloc(1, sizeof(*it));
    if (!it) return NULL;
    it->id = next_item_id++;
    it->count = count;
    it->price_cents = price_cents;
    strncpy(it->name, name, sizeof(it->name) - 1);
    it->next = NULL;
    return it;
}

static void inventory_push(struct Item *it) {
    if (!it) return;
    it->next = inventory_head;
    inventory_head = it;
}

static struct Item *inventory_find(int id) {
    for (struct Item *cur = inventory_head; cur; cur = cur->next) {
        if (cur->id == id) return cur;
    }
    return NULL;
}

static int inventory_update_count(int id, int delta) {
    struct Item *it = inventory_find(id);
    if (!it) return -1;
    if ((long)it->count + (long)delta < 0) return -2;
    it->count += delta;
    return it->count;
}

static int inventory_total_value_cents(void) {
    long total = 0;
    for (struct Item *cur = inventory_head; cur; cur = cur->next) {
        total += (long)cur->count * (long)cur->price_cents;
    }
    if (total > INT32_MAX) return INT32_MAX;
    return (int)total;
}

static void inventory_print_all(void) {
    printf("inventory:\n");
    for (struct Item *cur = inventory_head; cur; cur = cur->next) {
        printf("  #%d  x%-4d  $%.2f  %s\n",
               cur->id, cur->count, cur->price_cents / 100.0, cur->name);
    }
    printf("total value: $%.2f\n", inventory_total_value_cents() / 100.0);
}

static int inventory_remove(int id) {
    struct Item **p = &inventory_head;
    while (*p) {
        if ((*p)->id == id) {
            struct Item *doomed = *p;
            *p = doomed->next;
            free(doomed);
            return 0;
        }
        p = &((*p)->next);
    }
    return -1;
}

int main(int argc, char **argv) {
    inventory_push(item_new("widget",     10, 299));
    inventory_push(item_new("sprocket",    4, 1599));
    inventory_push(item_new("bolt-m4",   500, 7));
    inventory_push(item_new("adapter-usb", 2, 1999));

    inventory_print_all();

    if (argc >= 2 && strcmp(argv[1], "--restock") == 0) {
        inventory_update_count(1001, 16);
        inventory_update_count(1002, -100);
    }

    if (argc >= 2 && strcmp(argv[1], "--retire") == 0) {
        inventory_remove(1003);
    }

    inventory_print_all();

    struct Item *cur = inventory_head;
    while (cur) {
        struct Item *next = cur->next;
        free(cur);
        cur = next;
    }
    return 0;
}
