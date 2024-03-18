#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
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
        if (!block_store_request(bs, i + BITMAP_START_BLOCK)) {
            free(bs->fbm);
            free(bs);
            bitmap_destroy(overlay_bitmap);
            return NULL;
        }
    }

    // Cleanup the allocated memory for overlay_bitmap as it is now part of the block store
    bitmap_destroy(overlay_bitmap);

    // Return the initialized block store
    return bs;
}

void block_store_destroy(block_store_t *const bs) {
    if(bs != NULL){ //Checks to see if the pointer is not NULL
        free(bs->fbm);
        free(bs); //Frees the memory
    }
}

size_t block_store_allocate(block_store_t *const bs) {
    if (bs == NULL) {
        return SIZE_MAX;
    }

    // Find the zero.
    size_t index = bitmap_ffz(bs->fbm);

    if (index != SIZE_MAX) { // Check if a zero bit was found
        bitmap_set(bs->fbm, index);
        return index;
    } else { // No zero bit found
        return SIZE_MAX;
    }
}

bool block_store_request(block_store_t *const bs, size_t block_index) {
    // Null check
    if(!bs) {
        return false;
    }
    
    // Make sure the given ID is within the bounds of the bitmap
    if(block_index > BLOCK_STORE_NUM_BLOCKS) {
        return false;
    }

    // Check if the block is already allocated
    if(bitmap_test(bs->fbm, block_index)) {
        return false;
    }

    // Mark the block as allocated in the bitmap
    bitmap_set(bs->fbm, block_index);

    // Ensure it was allocated
    if(!bitmap_test(bs->fbm, block_index)) {
        return false;
    }
    
    return true;
}

void block_store_release(block_store_t *const bs, const size_t block_id) {
    // Null check
    if(!bs) {
        return ;
    }
    
    // Make sure the given ID is within the bounds of the bitmap
    if(block_id > BLOCK_STORE_NUM_BLOCKS) {
        return ;
    }

    // Do not need to check if it is set or not as the result is the same anyways.
    bitmap_reset(bs->fbm, block_id);
}


size_t block_store_get_used_blocks(const block_store_t *const bs) {
    // Null check.
    if(!bs) {
        return SIZE_MAX;
    }

    // Get number of used blocks
    return bitmap_total_set(bs->fbm);
}

size_t block_store_get_free_blocks(const block_store_t *const bs) {
    // Null check.
    if(!bs) {
        return SIZE_MAX;
    }

    return BLOCK_STORE_NUM_BLOCKS - block_store_get_used_blocks(bs);
}

size_t block_store_get_total_blocks() {
    return BLOCK_STORE_NUM_BLOCKS; //retuns the number of blocks
}

size_t block_store_read(const block_store_t *const bs, const size_t block_id, void *buffer) {
    if(!bs) {
        return 0;
    }

    // Null check for buffer.
    if(!buffer) {
        return 0;
    }

    // Is there another way we should do this that can check the size of the buffer?
    // Or do we assume the buffer is sized to at least fit a block?
    memcpy(buffer, &(bs->data[block_id]), BLOCK_SIZE_BYTES);

    return BLOCK_SIZE_BYTES;
}

size_t block_store_write(block_store_t *const bs, const size_t block_id, const void *buffer) {
    if(!bs) {
        return 0;
    }

    // Null check for buffer.
    if(!buffer) {
        return 0;
    }

    // Is there another way we should do this that can check the size of the buffer?
    // Or do we assume the buffer is sized to at least fit a block?
    memcpy(&(bs->data[block_id]), buffer, BLOCK_SIZE_BYTES);

    return BLOCK_SIZE_BYTES;
}

block_store_t *block_store_deserialize(const char *const filename) {
    // Check filename is not null
    if(!filename) { 
        return NULL;
    }

    // Create new block store, if failed return null.
    block_store_t *bs = NULL;
    bs = block_store_create();
    if(!bs) {
        return NULL;
    }
    
    // Open the file and store file descriptor.
    int fle = open(filename, O_RDONLY);
    if(fle == -1) {
        // Failed to open.
        return NULL;
    }

    // Read the data, block by block.
    // If that block is empty, do nothing
    // If that block is not empty, insert it into the bitmap.

    // Close the file.
    // Likely should be doing something else as well if we fail to close....
    if(close(fle) == -1) {
        return 0;
    }

    return bs;
}

size_t block_store_serialize(const block_store_t *const bs, const char *const filename) {
    // Null Check for data and filename
    if(!bs) {
        return 0;
    }

    if(!filename) { 
        return 0;
    }
    // Delete the old file if it exists.
    remove(filename);
    
    // Open the file and store file descriptor.
    int fle = open(filename, O_CREAT | O_WRONLY);
    if(fle == -1) {
        // Failed to open.
        return 0;
    }

    // Write the data. Returns number of bytes written. 
    size_t num_blocks_written = write(fle, bs->data, BLOCK_STORE_NUM_BLOCKS * BLOCK_SIZE_BYTES);

    // Close the file.
    // Likely should be doing something else as well if we fail to close....
    if(close(fle) == -1) {
        return 0;
    }

    return num_blocks_written;
}