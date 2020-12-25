#include <vector>
#include <string>
#include "dns_config.h"
#include "dns_utils.h"
#include "misc_log_ex.h"

namespace dns_config
{
    std::vector<std::string> m_seed_nodes;
    std::vector<std::string> m_txt_seed_nodes;
    std::vector<std::string> m_update;
    std::vector<std::string> m_download;
    bool m_dnssec_ok;
    tools::DNSResolver dr = tools::DNSResolver::create();

    void init(const bool testnet)
    {
        m_dnssec_ok = false;
        m_seed_nodes.clear();
        m_txt_seed_nodes.clear();
        m_update.clear();
        m_download.clear();

        bool dns_avail = false, dns_valid = false;
        std::vector<std::string> result;

        tools::DNSResolver dr = tools::DNSResolver::create();

        dr.get_ipv4(ROOT_DOMAIN, dns_avail, dns_valid);

        if (!dns_avail || !dns_valid)
            return;

        std::vector<std::string> seed_nodes = testnet ? testnet::SEED_NODES : SEED_NODES;
        std::vector<std::string> txt_seed_nodes = testnet ? testnet::TXT_SEED_NODES : TXT_SEED_NODES;

        for (auto &s : seed_nodes)
        {
            result = dr.get_ipv4(s, dns_avail, dns_valid);

            if (!dns_avail)
                MERROR("Server side DNS failure for " << s);
            else if (!dns_valid)
                MERROR("Client side DNS failure for " << s);

            if (!dns_avail || !dns_valid)
                continue;

            for (auto &r : result)
                m_seed_nodes.push_back(r);
        }

        tools::dns_utils::load_txt_records_from_dns(m_update, UPDATE);
        tools::dns_utils::load_txt_records_from_dns(m_download, DOWNLOAD);
        tools::dns_utils::load_txt_records_from_dns(m_txt_seed_nodes, txt_seed_nodes);

        for (auto &s : m_txt_seed_nodes)
            m_seed_nodes.push_back(s);

        if (m_seed_nodes.size() > 0 && m_update.size() > 0)
            m_dnssec_ok = true;
    }

    std::vector<std::string> get_update_records() { return m_update; }
    std::vector<std::string> get_download_records() { return m_download; }
    std::vector<std::string> get_seed_node_records() { return m_seed_nodes; }
    bool has_update_records() { return m_update.size() > 0; }
    bool has_download_records() { return m_download.size() > 0; }
    bool has_seed_node_records() { return m_seed_nodes.size() > 0; }
    bool is_dnssec_ok() { return m_dnssec_ok; }
}