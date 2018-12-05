/*
 * XMSS Private Key
 * An XMSS: Extended Hash-Based Siganture private key.
 * The XMSS private key does not support the X509 and PKCS7 standard. Instead
 * the raw format described in [1] is used.
 *
 *   [1] XMSS: Extended Hash-Based Signatures,
 *       draft-itrf-cfrg-xmss-hash-based-signatures-06
 *       Release: July 2016.
 *       https://datatracker.ietf.org/doc/
 *       draft-irtf-cfrg-xmss-hash-based-signatures/?include_text=1
 *
 * (C) 2016,2017 Matthias Gierlings
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 **/

#include "xmss_privatekey.h"
#include "xmss_signature_operation.h"
#include <cmath>
#if defined(BOTAN_TARGET_OS_HAS_THREADS)
   #include <thread>
#endif

namespace bpqcrypto {

	using Botan::Provider_Not_Found;

XMSS_PrivateKey::XMSS_PrivateKey(const secure_vector<uint8_t>& raw_key)
   : XMSS_PublicKey(unlock(raw_key)),
     XMSS_Common_Ops(XMSS_PublicKey::m_xmss_params.oid()),
     m_wots_priv_key(m_wots_params.oid(), m_public_seed),
     m_index_reg(XMSS_Index_Registry::get_instance())
   {
   BOTAN_ASSERT(sizeof(size_t) >= std::ceil(
      static_cast<float>(XMSS_PublicKey::m_xmss_params.tree_height()) / 8.f),
      "System type \"size_t\" not big enough to support"
      " leaf index.");

   if(raw_key.size() != size() && raw_key.size() != size_long())
      {
      throw Integrity_Failure("Invalid XMSS private key size detected.");
      }

   if(raw_key.size() == size_long())
      {
      BOTAN_ASSERT(raw_key.size() > size(),
         "raw_key.size() > size()");

      m_cached_hashtree = XMSS_HashTree(
			XMSS_PublicKey::m_xmss_params,
			raw_key.data() + size(), raw_key.size() - size());
      }

   // extract & copy unused leaf index from raw_key.
   uint64_t unused_leaf = 0;
   auto begin = (raw_key.begin() + XMSS_PublicKey::size());
   auto end = raw_key.begin() + XMSS_PublicKey::size() + sizeof(uint64_t);

   for(auto& i = begin; i != end; i++)
      {
      unused_leaf = ((unused_leaf << 8) | *i);
      }

   if(unused_leaf >= (1ull << XMSS_PublicKey::m_xmss_params.tree_height()))
       {
       throw Integrity_Failure("XMSS private key leaf index out of "
                               "bounds.");
       }

   begin = end;
   end = begin + XMSS_PublicKey::m_xmss_params.element_size();
   m_prf.clear();
   m_prf.reserve(XMSS_PublicKey::m_xmss_params.element_size());
   std::copy(begin, end, std::back_inserter(m_prf));

   begin = end;
   end = begin + m_wots_params.element_size();
   m_wots_priv_key.set_private_seed(secure_vector<uint8_t>(begin, end));
   set_unused_leaf_index(static_cast<size_t>(unused_leaf));

      // force building of hashtree
      XMSS_Address adrs;
      tree_hash(0,
                XMSS_PublicKey::m_xmss_params.tree_height(),
                adrs);
   }

XMSS_PrivateKey::XMSS_PrivateKey(
      XMSS_Parameters::xmss_algorithm_t xmss_algo_id,
      RandomNumberGenerator& rng)
   : XMSS_PublicKey(xmss_algo_id, rng),
     XMSS_Common_Ops(xmss_algo_id),
     m_wots_priv_key(XMSS_PublicKey::m_xmss_params.ots_oid(),
                     public_seed(),
                     rng),
     m_prf(rng.random_vec(XMSS_PublicKey::m_xmss_params.element_size())),
     m_index_reg(XMSS_Index_Registry::get_instance())
   {
   XMSS_Address adrs;
   set_root(tree_hash(0,
                      XMSS_PublicKey::m_xmss_params.tree_height(),
                      adrs));
   }

XMSS_PrivateKey::XMSS_PrivateKey(
   XMSS_Parameters::xmss_algorithm_t xmss_algo_id,
   size_t idx_leaf,
   const secure_vector<uint8_t>& wots_priv_seed,
   const secure_vector<uint8_t>& prf,
   const secure_vector<uint8_t>& public_seed)

   : XMSS_PublicKey(xmss_algo_id, secure_vector<uint8_t>(), public_seed)
   , XMSS_Common_Ops(xmss_algo_id)
   , m_wots_priv_key(XMSS_PublicKey::m_xmss_params.ots_oid(), public_seed, wots_priv_seed)
   , m_prf(prf)
   , m_index_reg(XMSS_Index_Registry::get_instance())
   {
      XMSS_Address adrs;
      set_root(tree_hash(0,
                       XMSS_PublicKey::m_xmss_params.tree_height(),
                       adrs));

      set_unused_leaf_index(idx_leaf);
   }

   secure_vector<uint8_t> XMSS_PrivateKey::tree_hash(size_t start_idx,
                        size_t target_node_height,
                        XMSS_Address& adrs)
   {
   BOTAN_ASSERT((start_idx % (1 << target_node_height)) == 0,
             "Start index must be divisible by 2^{target node height}.");

   if (!m_cached_hashtree.is_empty())
   {
      auto && hash = m_cached_hashtree.tree_hash(start_idx, target_node_height);
      if (!hash.empty())
            return hash;
   }
   else
   {
         m_cached_hashtree.allocate_tree(XMSS_PublicKey::m_xmss_params.tree_height());
   }

#if defined(BOTAN_TARGET_OS_HAS_THREADS)
   // dertermine number of parallel tasks to split the tree_hashing into.
   size_t split_level = std::min(
      {
      target_node_height,
      static_cast<size_t>(
         std::ceil(std::log2(XMSS_Tools::max_threads())))
      });

   // skip parallelization overhead for leaf nodes.
   if(split_level == 0)
      {
#endif
      secure_vector<uint8_t> result;
      tree_hash_subtree(result, start_idx, target_node_height, adrs);
      return result;
#if defined(BOTAN_TARGET_OS_HAS_THREADS)
      }

   size_t subtrees = 1 << split_level;
   size_t last_idx = static_cast<size_t>(1 << (target_node_height)) + start_idx;
   size_t offs = (last_idx - start_idx) / subtrees;
   uint8_t level = split_level; // current level in the tree

   BOTAN_ASSERT((last_idx - start_idx) % subtrees == 0,
                "Number of worker threads in tree_hash need to divide range "
                "of calculated nodes.");

   std::vector<secure_vector<uint8_t>> nodes(
       subtrees,
       secure_vector<uint8_t>(XMSS_PublicKey::m_xmss_params.element_size()));
   std::vector<XMSS_Address> node_addresses(subtrees, adrs);
   std::vector<XMSS_Hash> xmss_hash(subtrees, m_hash);
   std::vector<std::thread> threads;
   threads.reserve(subtrees);

   // Calculate multiple subtrees in parallel.
   for(size_t i = 0; i < subtrees; i++)
      {
      using tree_hash_subtree_fn_t =
         void (XMSS_PrivateKey::*)(secure_vector<uint8_t>&,
                                   size_t,
                                   size_t,
                                   XMSS_Address&,
                                   XMSS_Hash&);

      threads.emplace_back(
         std::thread(
            static_cast<tree_hash_subtree_fn_t>(
               &XMSS_PrivateKey::tree_hash_subtree),
            this,
            std::ref(nodes[i]),
            start_idx + i * offs,
            target_node_height - split_level,
            std::ref(node_addresses[i]),
            std::ref(xmss_hash[i])));
      }

   for(auto& t : threads)
      {
      t.join();
      }

   threads.clear();

   // Parallelize the top tree levels horizontally
   while(level-- > 1)
      {
      std::vector<secure_vector<uint8_t>> ro_nodes(
         nodes.begin(), nodes.begin() + (1 << (level+1)));

      for(size_t i = 0; i < (1U << level); i++)
         {
         node_addresses[i].set_tree_height(target_node_height - (level + 1));
         node_addresses[i].set_tree_index(
            (node_addresses[2 * i + 1].get_tree_index() - 1) >> 1);
         using rnd_tree_hash_fn_t =
            void (XMSS_PrivateKey::*)(secure_vector<uint8_t>&,
                                      const secure_vector<uint8_t>&,
                                      const secure_vector<uint8_t>&,
                                      XMSS_Address& adrs,
                                      const secure_vector<uint8_t>&,
                                      XMSS_Hash&);

         threads.emplace_back(
            std::thread(
               static_cast<rnd_tree_hash_fn_t>(
                  &XMSS_PrivateKey::randomize_tree_hash),
               this,
               std::ref(nodes[i]),
               std::ref(ro_nodes[2 * i]),
               std::ref(ro_nodes[2 * i + 1]),
               std::ref(node_addresses[i]),
               std::ref(this->public_seed()),
               std::ref(xmss_hash[i])));
         }
      for(auto &t : threads)
         {
         t.join();
         }
      threads.clear();

      for(size_t i = 0; i < (1U << level); i++)
            {
            size_t node_level = target_node_height - level;
            size_t offs = 1U << node_level;
            m_cached_hashtree.set_hash(start_idx + i * offs, node_level, nodes[i]);
            }
      
      }

   // Avoid creation an extra thread to calculate root node.
   node_addresses[0].set_tree_height(target_node_height - 1);
   node_addresses[0].set_tree_index(
      (node_addresses[1].get_tree_index() - 1) >> 1);
   randomize_tree_hash(nodes[0],
                       nodes[0],
                       nodes[1],
                       node_addresses[0],
                       this->public_seed());

   m_cached_hashtree.set_hash(start_idx, target_node_height, nodes[0]);
                       
   return nodes[0];
#endif
   }

void
XMSS_PrivateKey::tree_hash_subtree(secure_vector<uint8_t>& result,
                                   size_t start_idx,
                                   size_t target_node_height,
                                   XMSS_Address& adrs,
                                   XMSS_Hash& hash)
   {
   const secure_vector<uint8_t>& seed = this->public_seed();

   std::vector<secure_vector<uint8_t>> nodes(
      target_node_height + 1,
      secure_vector<uint8_t>(XMSS_PublicKey::m_xmss_params.element_size()));

   // node stack, holds all nodes on stack and one extra "pending" node. This
   // temporary node referred to as "node" in the XMSS standard document stays
   // a pending element, meaning it is not regarded as element on the stack
   // until level is increased.
   std::vector<uint8_t> node_levels(target_node_height + 1);

   uint8_t level = 0; // current level on the node stack.
   XMSS_WOTS_PublicKey pk(m_wots_priv_key.wots_parameters().oid(), seed);
   size_t last_idx = static_cast<size_t>(1 << target_node_height) + start_idx;

   for(size_t i = start_idx; i < last_idx; i++)
      {
      adrs.set_type(XMSS_Address::Type::OTS_Hash_Address);
      adrs.set_ots_address(i);
      this->wots_private_key().generate_public_key(
         pk,
         // getWOTS_SK(SK, s + i), reference implementation uses adrs
         // instead of zero padded index s + i.
         this->wots_private_key().at(adrs, hash),
         adrs,
         hash);
      adrs.set_type(XMSS_Address::Type::LTree_Address);
      adrs.set_ltree_address(i);
      create_l_tree(nodes[level], pk, adrs, seed, hash);
      node_levels[level] = 0;

      m_cached_hashtree.set_hash(i, 0, nodes[level]);

      adrs.set_type(XMSS_Address::Type::Hash_Tree_Address);
      adrs.set_tree_height(0);
      adrs.set_tree_index(i);

      while(level > 0 && node_levels[level] ==
            node_levels[level - 1])
         {
         adrs.set_tree_index(((adrs.get_tree_index() - 1) >> 1));
         randomize_tree_hash(nodes[level - 1],
                             nodes[level - 1],
                             nodes[level],
                             adrs,
                             seed,
                             hash);

         size_t node_level = node_levels[level-1] + 1;
         size_t node_index = i >> node_level;
         size_t idx = node_index << node_level;
         m_cached_hashtree.set_hash(idx, node_level, nodes[level-1]);

         node_levels[level - 1]++;
         level--; //Pop stack top element
         adrs.set_tree_height(adrs.get_tree_height() + 1);
         }
      level++; //push temporary node to stack
      }
   result = nodes[level - 1];
   }

std::shared_ptr<Botan::Atomic<size_t>>
XMSS_PrivateKey::recover_global_leaf_index() const
   {
   BOTAN_ASSERT(m_wots_priv_key.private_seed().size() ==
                XMSS_PublicKey::m_xmss_params.element_size() &&
                m_prf.size() == XMSS_PublicKey::m_xmss_params.element_size(),
                "Trying to retrieve index for partially initialized "
                "key.");
   return m_index_reg.get(m_wots_priv_key.private_seed(),
                          m_prf);
   }

secure_vector<uint8_t> XMSS_PrivateKey::raw_private_key() const
{
	std::vector<uint8_t> pk { raw_public_key() };
	secure_vector<uint8_t> result(pk.begin(), pk.end());
	result.reserve(size());

    //size_t leaf_index = unused_leaf_index();
	size_t leaf_index = 0;

	for(int i = 7; i >= 0; i--)
	{
		result.push_back( static_cast<uint8_t>(
			static_cast<uint64_t>(leaf_index) >> 8 * i)
		);
	}

	std::copy(m_prf.begin(), m_prf.end(), std::back_inserter(result));
	std::copy(m_wots_priv_key.private_seed().begin(), m_wots_priv_key.private_seed().end(),
		std::back_inserter(result));

	return result;
}

secure_vector<uint8_t> XMSS_PrivateKey::sign(RandomNumberGenerator & rng, uint8_t const * msg, size_t msg_size)
{
	XMSS_Signature_Operation op(*this);
	op.update(msg, msg_size);
	return op.sign(rng);
}


}
