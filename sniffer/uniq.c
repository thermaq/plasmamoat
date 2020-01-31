#include<stdio.h>
#include<stdlib.h>

#define PERTURB_SHIFT 5
#define THRESHOLD_MULTIPLIER 1.5 // about 70% of the table is filled


unsigned int hash(unsigned int x) {
    x = ((x >> 16) ^ x) * 0x45d9f3b;
    x = ((x >> 16) ^ x) * 0x45d9f3b;
    x = (x >> 16) ^ x;
    return x;
}

int insert_ip_into_table(int ip, unsigned int * table, int size) {
    unsigned int h = hash(ip);
    int i=0, loc;

    for (unsigned int perturb = h; perturb >>= PERTURB_SHIFT;) { // just like python
        i = (i << 2) + i + perturb + 1;
        loc = i % size;
        if (table[loc] == 0) {
            table[loc] = ip;
            return 1;
        }
        if (table[loc] == ip) {
            return 0;
        }
    }
    return 0;
}

unsigned int * resize_table(unsigned int *old_table, int old_size, int new_size) {
    unsigned int * new_table = calloc(new_size, sizeof(unsigned int));

    for (int i=0; i<old_size; i++) {
        insert_ip_into_table(
            old_table[i],
            new_table,
            new_size
        );
    }
    return new_table;
}

int main() {
    unsigned int ip;
    char c;
    int size = 8;
    unsigned int *table = calloc(size, sizeof(unsigned int));
    int filled_buckets = 0;
    int added;

    while (1) {
        if (THRESHOLD_MULTIPLIER * filled_buckets > size) {
            table = resize_table(table, size, size*2);
            size *= 2;
        }
        ip=0;
        c=getchar_unlocked();
        while(c>='0' && c<='9') {
            ip = (ip*10) + (c-'0');
            c=getchar_unlocked();
        }
        if (ip>0) {
            added = insert_ip_into_table(ip, table, size);
            if (added == 1) {
                filled_buckets++;
                printf("%d\n", ip);
            } 
        }
    }
    return 0;
}
