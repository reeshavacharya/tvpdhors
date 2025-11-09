#ifndef BFTVMHORS_MHT_H
#define BFTVMHORS_MHT_H

#include <bftvmhors/types.h>

#define MHT_GENERATE_AUTH_PATH 0
#define MHT_NOT_GENERATE_AUTH_PATH 1



typedef struct mht_node{
    void * data;        /* Pointer to the MHT data */
    u32 data_size;      /* Size of the MHT data */
    u32 level;          /* Level of the MHT node. 0 is the leaf level and increases up to the root node level */
    u32 id;             /* ID of a leaf is used for generating the authentication path.
                         * ID is ignored (0) for non-leaf nodes */
}mht_node_t;


/// Build a MHT upon the given input
/// \param input Pointer to the input
/// \param num_blocks Number of blocks in the input
/// \param block_size Size of each block in the input
/// \param do_generate_auth_path If MHT_GENERATE_AUTH_PATH, it generates a auth path too
/// \param auth_path_target_node The node for which we want to generate the auth path
/// \param auth_path Pointer to the buffer where we write the values of the nodes in the auth path
/// \return MHT root node
mht_node_t *mht_build(const u8 *input, u32 num_blocks, u32 block_size, u32 do_generate_auth_path,
                      u32 auth_path_target_node, u8 * auth_path);

/// Destroys the MHT node
/// \param node Pointer to the MHT node
void mht_destroy_node(mht_node_t *node);

#endif