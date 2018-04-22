// Copyright (c) 2018 The Bitcoin Post-Quantum developers

#ifndef BPQ_XMSS_HASHTREE_H_
#define BPQ_XMSS_HASHTREE_H_

#include <botan/types.h>
#include "xmss_parameters.h"

namespace bpqcrypto {

    class XMSS_HashTree
    {
    public:

        XMSS_HashTree()
        {
        }

        XMSS_HashTree(XMSS_HashTree const & b)
            : m_tree(b.m_tree)
        {
        }

        XMSS_HashTree(XMSS_HashTree && b)
            : m_tree(std::move(b.m_tree))
        {
        }

        XMSS_HashTree(XMSS_Parameters const & params, 
            uint8_t const * raw_data, size_t raw_size)
        {
            if (raw_size > 0)
            {
                m_tree.resize(params.tree_height()+1);

                size_t raw_index = 0;
                size_t level_size = 1U << params.tree_height();

                for (size_t level = 0; level <= params.tree_height(); ++level)
                {
                    m_tree[level].resize(level_size);

                    for(size_t i = 0; i < level_size; ++i)
                    {
                        BOTAN_ASSERT(raw_index + level_size <= raw_size,
                            "raw_hash is too small to contain all tree.");

                        m_tree[level][i].assign(raw_data + raw_index, raw_data + raw_index + params.element_size());

                        raw_index += params.element_size();
                    }

                    level_size /= 2;
                }
            }
        }

        XMSS_HashTree & operator=(XMSS_HashTree && b)
        {
            if (this != &b)
            {
                m_tree = std::move(b.m_tree);
            }
            return *this;
        }

        bool is_empty() const 
        {
            return m_tree.empty();
        }

        static size_t size(XMSS_Parameters const & params)
        {
            return ((1U << params.tree_height()) * 2 - 1) * params.element_size();
        }

        size_t size() const
        {
            if ( m_tree.empty() )
                return 0;
            
            size_t tree_height = m_tree.size()-1;
            size_t element_size = m_tree[0][0].size();
            return ((1U << tree_height) * 2 - 1) * element_size;
        }

        secure_vector<uint8_t> raw_hashtree() const
        {
            if ( m_tree.empty() )
                return {};

            secure_vector<uint8_t> raw_hash;
            size_t tree_height = m_tree.size()-1;
            size_t element_size = m_tree[0][0].size();

            raw_hash.reserve( ((1U << tree_height) * 2 - 1) * element_size);

            // store hashes from tree, begining from level 0
            for (auto && level : m_tree)
            {
                for(auto && hash : level)
                {
                    BOTAN_ASSERT(hash.size() == element_size,
                        "each hash value in tree must be set.");
                    raw_hash.insert(raw_hash.end(), hash.begin(), hash.end());
                }
            }

            return raw_hash;
        }

        void set_hash(size_t start_idx, size_t node_height, secure_vector<uint8_t> const & hash)
        {
            size_t level = node_height;
            size_t level_index = start_idx >> node_height;
            m_tree[level][level_index].assign(hash.begin(), hash.end());
        }

        secure_vector<uint8_t> const & tree_hash(
            size_t start_idx, size_t target_node_height) const
        {
            size_t tree_height = m_tree.size();

            BOTAN_ASSERT((start_idx % (1 << target_node_height)) == 0,
                "Start index must be divisible by 2^{target node height}.");
            
            BOTAN_ASSERT(target_node_height < tree_height,
                "target_node_height must be less then tree_height.");
                          
            size_t level_index = start_idx >> target_node_height;
            return m_tree[target_node_height][level_index];
        }

        void allocate_tree(size_t tree_height)
        {
            m_tree.resize(tree_height+1);
            size_t level_size = 1 << tree_height;
            for (size_t level = 0; level <= tree_height; ++level)
            {
                m_tree[level].resize(level_size);
                level_size /= 2;
            }
        }

    private:

        std::vector<std::vector<secure_vector<uint8_t>>> m_tree;
    };

}

#endif // BOTAN_XMSS_HASHTREE_H_
