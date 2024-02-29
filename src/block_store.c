#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "bitmap.h"
#include "block_store.h"
// include more if you need

// You might find this handy.  I put it around unused parameters, but you should
// remove it before you submit. Just allows things to compile initially.
#define UNUSED(x) (void)(x)

// Internal structure of the block store (opaque to users)
struct block_store {
    uint8_t data[BLOCK_STORE_NUM_BYTES];
};

block_store_t *block_store_create() {
    // Allocate memory for the block store
    block_store_t *bs = (block_store_t *)malloc(sizeof(block_store_t));
    if (bs == NULL) return NULL;

    // Initialize the block store to zeros
    memset(bs->data, 0, BLOCK_STORE_NUM_BYTES);

    // Set the bitmap field starting at index BITMAP_START_BLOCK
    size_t bitmap_start_block = BLOCK_SIZE_BITS / BLOCK_SIZE_BYTES; // Convert bits to bytes
    uint8_t *bitmap = bs->data + (bitmap_start_block * BLOCK_SIZE_BYTES);

    // Overlay the bitmap on the blocks
    memset(bitmap, 0, BITMAP_SIZE_BYTES);

    // Mark blocks used by the bitmap as allocated
    size_t i;
    for (i = 0; i < BLOCK_STORE_AVAIL_BLOCKS; ++i) {
        if (!block_store_request(bs, i)) {
            // Allocation error, free memory and return NULL
            free(bs);
            return NULL;
        }
    }

    return bs;
}

void block_store_destroy(block_store_t *const bs)
{
    if(bs != NULL){ //Checks to see if the pointer is not NULL
        free(bs); //Frees the memory
    }
}

size_t block_store_allocate(block_store_t *const bs)
{
    UNUSED(bs);
    return 0;
}

bool block_store_request(block_store_t *const bs, size_t block_index) {
    // Calculate the byte and bit offset for the block in the bitmap
    size_t byte_offset = block_index / 8;
    size_t bit_offset = block_index % 8;

    // Check if the block is already allocated
    if ((bs->data[byte_offset] & (1 << bit_offset)) != 0) {
        return false;
    }

    // Mark the block as allocated in the bitmap
    bs->data[byte_offset] |= (1 << bit_offset);
    
    return true;
}

void block_store_release(block_store_t *const bs, const size_t block_id)
{
    UNUSED(bs);
    UNUSED(block_id);
}

size_t block_store_get_used_blocks(const block_store_t *const bs)
{
    UNUSED(bs);
    return 0;
}

size_t block_store_get_free_blocks(const block_store_t *const bs)
{
    UNUSED(bs);
    return 0;
}

size_t block_store_get_total_blocks()
{
    return 0;
}

size_t block_store_read(const block_store_t *const bs, const size_t block_id, void *buffer)
{
    UNUSED(bs);
    UNUSED(block_id);
    UNUSED(buffer);
    return 0;
}

size_t block_store_write(block_store_t *const bs, const size_t block_id, const void *buffer)
{
    UNUSED(bs);
    UNUSED(block_id);
    UNUSED(buffer);
    return 0;
}

block_store_t *block_store_deserialize(const char *const filename)
{
    UNUSED(filename);
    return NULL;
}

size_t block_store_serialize(const block_store_t *const bs, const char *const filename)
{
    UNUSED(bs);
    UNUSED(filename);
    return 0;
}