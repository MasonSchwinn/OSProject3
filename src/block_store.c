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
    bitmap_t *fbm;
};

block_store_t *block_store_create() {
    // Allocate memory for the block store
    block_store_t *bs = (block_store_t *)malloc(sizeof(block_store_t));
    if (bs == NULL) return NULL;

    // Initialize the block store to zeros
    memset(bs->data, 0, BLOCK_STORE_NUM_BYTES);

    // Create and initialize the Free Block Map (FBM)
    bitmap_t *fbm = bitmap_create(BITMAP_SIZE_BITS);
    bs->fbm = fbm;
    if (bs->fbm == NULL) {
        free(bs);
        return NULL;
    }

    // Set the bitmap field starting at index BITMAP_START_BLOCK
    size_t bitmap_start_block = BITMAP_START_BLOCK;
    uint8_t *bitmap_data = bs->data + (bitmap_start_block * BLOCK_SIZE_BYTES);
    bitmap_t *overlay_bitmap = bitmap_overlay(BITMAP_SIZE_BITS, bitmap_data);
    if (overlay_bitmap == NULL) {
        free(bs->fbm);
        free(bs);
        return NULL;
    }

    // Mark blocks used by the FBM as allocated
    size_t i;
    for (i = 0; i < BITMAP_NUM_BLOCKS; ++i) {
        if (!block_store_request(bs, i)) {
            free(bs->fbm);
            free(bs);
            bitmap_destroy(overlay_bitmap);
            return NULL;
        }
    }

    // Cleanup the allocated memory for overlay_bitmap as it is now part of the block store
    bitmap_destroy(overlay_bitmap);

    return bs;
}

void block_store_destroy(block_store_t *const bs)
{
    if(bs != NULL){ //Checks to see if the pointer is not NULL
        free(bs->fbm);
        free(bs); //Frees the memory
    }
}

size_t block_store_allocate(block_store_t *const bs)
{
    if (bs == NULL){ //Error check
        return SIZE_MAX;
    }

    size_t index = bitmap_ffz(bs->fbm); //Finds the first zero
    if(index != SIZE_MAX){ //Checks to see if the first zero was found
        bitmap_set(bs->fbm,index); //Sets the bitmap
    }

    return index; //returns the index
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