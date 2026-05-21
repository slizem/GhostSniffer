#define _CRT_SECURE_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS

#include <iostream>
#include <string>
#include <conio.h>
#include <winsock2.h>
#include <windows.h>
#include <pcap.h>
#include <iphlpapi.h>
#include <tcpmib.h>
#include <vector>
#include <map>
#include <set>
#include <algorithm>

#pragma comment(lib, "wpcap.lib")
#pragma comment(lib, "Packet.lib")
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")

volatile bool running = true;
volatile bool paused = false;
volatile bool detailed_mode = true;
volatile bool return_to_menu = false;
pcap_t* global_handle = nullptr;
HANDLE hConsole;
std::string target_domain;
bool monitor_specific_domain = false;
std::map<std::string, std::string> dns_cache;
std::map<std::string, int> ip_packet_count;
std::map<std::string, int> ip_byte_count;
std::set<std::string> target_ips;
int packet_count = 0;

void SetLightBlue() { SetConsoleTextAttribute(hConsole, 11); }
void SetWhite() { SetConsoleTextAttribute(hConsole, 15); }
void SetGray() { SetConsoleTextAttribute(hConsole, 7); }
void SetGreen() { SetConsoleTextAttribute(hConsole, 10); }
void SetYellow() { SetConsoleTextAttribute(hConsole, 14); }
void SetRed() { SetConsoleTextAttribute(hConsole, 12); }

void HideCursor() {
    CONSOLE_CURSOR_INFO cursorInfo;
    GetConsoleCursorInfo(hConsole, &cursorInfo);
    cursorInfo.bVisible = FALSE;
    SetConsoleCursorInfo(hConsole, &cursorInfo);
}

void ClearLine(int y) {
    COORD pos = { 0, (SHORT)y };
    SetConsoleCursorPosition(hConsole, pos);
    for (int i = 0; i < 120; i++) std::cout << " ";
    SetConsoleCursorPosition(hConsole, pos);
}

int ShowMenu(const std::vector<std::string>& options, const std::string& title, int start_line) {
    int selected = 0;
    int key;

    while (true) {
        COORD pos = { 0, (SHORT)start_line };
        SetConsoleCursorPosition(hConsole, pos);

        SetLightBlue();
        std::cout << title << "\n\n";
        SetWhite();

        for (size_t i = 0; i < options.size(); i++) {
            ClearLine(start_line + static_cast<int>(i) + 3);
            SetConsoleCursorPosition(hConsole, { (SHORT)0, (SHORT)(start_line + static_cast<int>(i) + 3) });

            if (static_cast<size_t>(selected) == i) {
                SetLightBlue();
                std::cout << "> " << options[i];
                SetWhite();
            }
            else {
                SetGray();
                std::cout << "  " << options[i];
                SetWhite();
            }
        }

        int hint_line = start_line + static_cast<int>(options.size()) + 4;
        ClearLine(hint_line);
        SetConsoleCursorPosition(hConsole, { 0, (SHORT)hint_line });
        SetGray();
        std::cout << "  СТРЕЛКИ - выбор  ENTER - подтвердить  ESC - назад";
        SetWhite();

        key = _getch();

        if (key == 224) {
            key = _getch();
            switch (key) {
            case 72: if (selected > 0) selected--; break;
            case 80: if (selected < static_cast<int>(options.size() - 1)) selected++; break;
            }
        }
        else if (key == 13) {
            for (int i = start_line; i <= hint_line; i++) {
                ClearLine(i);
            }
            return selected;
        }
        else if (key == 27) {
            for (int i = start_line; i <= hint_line; i++) {
                ClearLine(i);
            }
            return -1;
        }
    }
}

struct IPRange {
    std::string prefix;
    std::string country;
    std::string provider;
};

std::vector<IPRange> ip_database = {
    {"87.240.", "RU", "VKontakte"},
    {"5.61.", "RU", "VKontakte"},
    {"95.213.", "RU", "VKontakte"},
    {"93.186.", "RU", "Mail.ru"},
    {"217.69.", "RU", "Mail.ru"},
    {"8.8.", "US", "Google DNS"},
    {"1.1.1.", "AU", "Cloudflare DNS"},
    {"208.67.", "US", "OpenDNS"},
    {"17.", "US", "Apple"},
    {"31.13.", "US", "Facebook"},
    {"157.240.", "US", "Facebook"},
    {"69.171.", "US", "Facebook"},
    {"74.125.", "US", "Google"},
    {"142.250.", "US", "Google"},
    {"172.217.", "US", "Google"},
    {"216.58.", "US", "Google"},
    {"52.", "US", "Amazon AWS"},
    {"54.", "US", "Amazon AWS"},
    {"13.", "US", "Amazon AWS"},
    {"104.16.", "US", "Cloudflare"},
    {"104.17.", "US", "Cloudflare"},
    {"104.18.", "US", "Cloudflare"},
    {"104.19.", "US", "Cloudflare"},
    {"104.20.", "US", "Cloudflare"},
    {"104.21.", "US", "Cloudflare"},
    {"104.22.", "US", "Cloudflare"},
    {"104.23.", "US", "Cloudflare"},
    {"104.24.", "US", "Cloudflare"},
    {"104.25.", "US", "Cloudflare"},
    {"104.26.", "US", "Cloudflare"},
    {"104.27.", "US", "Cloudflare"},
    {"104.28.", "US", "Cloudflare"},
    {"104.29.", "US", "Cloudflare"},
    {"104.30.", "US", "Cloudflare"},
    {"104.31.", "US", "Cloudflare"},
    {"91.108.", "GB", "Telegram"},
    {"149.154.", "GB", "Telegram"},
    {"185.76.", "US", "Twitter/X"},
    {"104.244.", "US", "Twitter/X"},
    {"140.82.", "US", "GitHub"},
    {"192.168.", "LOCAL", "Локальная сеть"},
    {"10.", "LOCAL", "Локальная сеть"},
    {"172.16.", "LOCAL", "Локальная сеть"},
    {"127.", "LOCAL", "Локальный компьютер"}
};

std::string GetCountryAndProvider(const std::string& ip) {
    for (const auto& range : ip_database) {
        if (ip.find(range.prefix) == 0) {
            return range.country + " " + range.provider;
        }
    }
    return "";
}

std::string GetProtocolByPort(int port) {
    switch (port) {
    case 80: return "HTTP";
    case 443: return "HTTPS";
    case 22: return "SSH";
    case 21: return "FTP";
    case 25: return "SMTP";
    case 53: return "DNS";
    case 110: return "POP3";
    case 143: return "IMAP";
    case 993: return "IMAPS";
    case 995: return "POP3S";
    case 3389: return "RDP";
    case 8080: return "HTTP-Alt";
    case 8443: return "HTTPS-Alt";
    case 6881: case 6882: case 6883: case 6884:
    case 6885: case 6886: case 6887: case 6888: case 6889:
        return "BitTorrent";
    case 3478: case 3479: case 19302: case 19303:
        return "STUN/VoIP";
    default:
        if (port >= 6881 && port <= 6889) return "BitTorrent";
        if (port >= 3478 && port <= 3481) return "STUN/VoIP";
        if (port >= 16384 && port <= 32767) return "RTP/VoIP";
        return "";
    }
}

std::string GetOSByTTL(int ttl) {
    if (ttl <= 64) return "Linux/Android";
    if (ttl <= 128) return "Windows";
    if (ttl >= 255) return "Сетевое устройство";
    return "";
}

std::string GetProcessByPort(int port, bool is_tcp) {
    if (!is_tcp) return "";

    DWORD size = 0;
    GetExtendedTcpTable(NULL, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);

    std::vector<BYTE> buffer(size);
    PMIB_TCPTABLE_OWNER_PID tcp_table = (PMIB_TCPTABLE_OWNER_PID)buffer.data();

    if (GetExtendedTcpTable(tcp_table, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) != NO_ERROR) {
        return "";
    }

    for (DWORD i = 0; i < tcp_table->dwNumEntries; i++) {
        if (ntohs((u_short)tcp_table->table[i].dwLocalPort) == port) {
            HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, tcp_table->table[i].dwOwningPid);
            if (process) {
                char name[MAX_PATH] = "";
                DWORD len = MAX_PATH;
                if (QueryFullProcessImageNameA(process, 0, name, &len)) {
                    CloseHandle(process);
                    std::string full_path(name);
                    size_t pos = full_path.find_last_of("\\");
                    if (pos != std::string::npos) {
                        return full_path.substr(pos + 1) + " (PID:" + std::to_string(tcp_table->table[i].dwOwningPid) + ")";
                    }
                }
                CloseHandle(process);
            }
        }
    }
    return "";
}

std::string ExtractSNI(const u_char* data, int len) {
    if (len < 43) return "";
    if (data[0] != 0x16) return "";
    if (data[5] != 0x01) return "";

    int pos = 43;
    if (pos >= len) return "";
    u_char session_id_len = data[pos];
    pos += 1 + session_id_len;

    if (pos + 2 >= len) return "";
    u_short cipher_len = ntohs(*(u_short*)(data + pos));
    pos += 2 + cipher_len;

    if (pos >= len) return "";
    u_char comp_len = data[pos];
    pos += 1 + comp_len;

    if (pos + 2 >= len) return "";
    u_short ext_len = ntohs(*(u_short*)(data + pos));
    pos += 2;

    int end_pos = pos + ext_len;
    if (end_pos > len) end_pos = len;

    while (pos + 4 <= end_pos) {
        u_short ext_type = ntohs(*(u_short*)(data + pos));
        u_short ext_length = ntohs(*(u_short*)(data + pos + 2));

        if (ext_type == 0x0000) {
            int sni_pos = pos + 4;
            if (sni_pos + 5 > end_pos) return "";
            sni_pos += 2;

            if (sni_pos + 3 > end_pos) return "";
            u_char name_type = data[sni_pos];
            u_short name_len = ntohs(*(u_short*)(data + sni_pos + 1));

            if (name_type == 0 && sni_pos + 3 + name_len <= end_pos) {
                return std::string(reinterpret_cast<const char*>(data + sni_pos + 3), name_len);
            }
        }
        pos += 4 + ext_length;
    }
    return "";
}

std::string ExtractHostFromHTTP(const u_char* data, int len) {
    std::string payload(reinterpret_cast<const char*>(data), len);
    size_t pos = payload.find("Host: ");
    if (pos != std::string::npos) {
        pos += 6;
        size_t end = payload.find("\r\n", pos);
        if (end != std::string::npos) {
            return payload.substr(pos, end - pos);
        }
    }
    return "";
}

bool CheckDNSForDomain(const u_char* data, int len) {
    if (len < 12) return false;

    std::string domain_in_packet;
    int pos = 12;

    while (pos < len) {
        u_char label_len = data[pos];
        if (label_len == 0) break;
        if (label_len > 63 || (pos + 1 + label_len) > len) break;

        pos++;
        for (int i = 0; i < label_len && pos < len; i++) {
            domain_in_packet += tolower(data[pos]);
            pos++;
        }
        domain_in_packet += '.';
    }

    if (!domain_in_packet.empty() && domain_in_packet.back() == '.') {
        domain_in_packet.pop_back();
    }

    std::string target_lower = target_domain;
    std::transform(target_lower.begin(), target_lower.end(), target_lower.begin(), ::tolower);

    bool found = domain_in_packet.find(target_lower) != std::string::npos;

    if (found) {
        int answer_pos = 12;
        u_short qdcount = ntohs(*(u_short*)(data + 4));
        while (qdcount > 0 && answer_pos < len) {
            u_char label_len = data[answer_pos];
            if (label_len == 0) {
                answer_pos++;
                answer_pos += 4;
                qdcount--;
                break;
            }
            answer_pos += label_len + 1;
        }

        u_short ancount = ntohs(*(u_short*)(data + 6));
        while (ancount > 0 && answer_pos + 10 < len) {
            if ((data[answer_pos] & 0xC0) == 0xC0) {
                answer_pos += 2;
            }
            else {
                while (answer_pos < len && data[answer_pos] != 0) {
                    answer_pos += data[answer_pos] + 1;
                }
                answer_pos++;
            }

            u_short type = ntohs(*(u_short*)(data + answer_pos));
            u_short rdlength = ntohs(*(u_short*)(data + answer_pos + 8));

            if (type == 1 && rdlength == 4) {
                std::string ip = std::to_string((int)(unsigned char)data[answer_pos + 10]) + "." +
                    std::to_string((int)(unsigned char)data[answer_pos + 11]) + "." +
                    std::to_string((int)(unsigned char)data[answer_pos + 12]) + "." +
                    std::to_string((int)(unsigned char)data[answer_pos + 13]);
                target_ips.insert(ip);
            }

            answer_pos += 10 + rdlength;
            ancount--;
        }
    }

    return found;
}

bool IsLocalIP(const std::string& ip) {
    return ip.find("192.168.") == 0 || ip.find("10.") == 0 ||
        ip.find("172.16.") == 0 || ip.find("127.") == 0;
}

void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data) {
    if (!running || paused) return;

    packet_count++;

    if (header->len < 14) return;

    u_short ethertype = ntohs(*(u_short*)(pkt_data + 12));
    if (ethertype != 0x0800 || header->len < 34) return;

    u_char* src_ip = (u_char*)(pkt_data + 26);
    u_char* dst_ip = (u_char*)(pkt_data + 30);
    u_char protocol = pkt_data[23];
    u_char ttl = pkt_data[22];

    std::string src_ip_str = std::to_string((int)src_ip[0]) + "." +
        std::to_string((int)src_ip[1]) + "." +
        std::to_string((int)src_ip[2]) + "." +
        std::to_string((int)src_ip[3]);

    std::string dst_ip_str = std::to_string((int)dst_ip[0]) + "." +
        std::to_string((int)dst_ip[1]) + "." +
        std::to_string((int)dst_ip[2]) + "." +
        std::to_string((int)dst_ip[3]);

    bool outgoing = IsLocalIP(src_ip_str);
    std::string remote_ip = outgoing ? dst_ip_str : src_ip_str;

    ip_packet_count[remote_ip]++;
    ip_byte_count[remote_ip] += header->len;

    if (monitor_specific_domain && !target_domain.empty()) {
        bool is_target = false;
        std::string detected_domain;

        if (target_ips.find(src_ip_str) != target_ips.end() ||
            target_ips.find(dst_ip_str) != target_ips.end()) {
            is_target = true;
        }

        if (protocol == 17 && header->len >= 42) {
            u_short src_port = ntohs(*(u_short*)(pkt_data + 34));
            u_short dst_port = ntohs(*(u_short*)(pkt_data + 36));

            if (src_port == 53 || dst_port == 53) {
                int ip_len = (pkt_data[14] & 0x0F) * 4;
                int data_offset = 14 + ip_len + 8;

                if (data_offset < header->len) {
                    if (CheckDNSForDomain(pkt_data + data_offset, header->len - data_offset)) {
                        is_target = true;
                    }
                }
            }
        }

        if (protocol == 6 && header->len >= 54) {
            u_short dst_port = ntohs(*(u_short*)(pkt_data + 36));

            if (dst_port == 443) {
                int ip_len = (pkt_data[14] & 0x0F) * 4;
                int tcp_len = ((pkt_data[14 + ip_len + 12] >> 4) & 0x0F) * 4;
                int data_offset = 14 + ip_len + tcp_len;

                if (data_offset < header->len) {
                    std::string sni = ExtractSNI(pkt_data + data_offset, header->len - data_offset);
                    if (!sni.empty()) {
                        std::string sni_lower = sni;
                        std::transform(sni_lower.begin(), sni_lower.end(), sni_lower.begin(), ::tolower);
                        std::string target_lower = target_domain;
                        std::transform(target_lower.begin(), target_lower.end(), target_lower.begin(), ::tolower);

                        if (sni_lower.find(target_lower) != std::string::npos) {
                            is_target = true;
                            detected_domain = sni;
                            target_ips.insert(dst_ip_str);
                        }
                    }
                }
            }
        }

        if (!is_target) return;
    }

    SYSTEMTIME st;
    GetLocalTime(&st);

    if (!detailed_mode) {
        printf("%02d:%02d:%02d.%03d ", st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
        SetLightBlue();
        std::cout << "#" << packet_count << " ";
        SetWhite();

        if (outgoing) {
            SetGreen();
            std::cout << "OUT ";
            SetWhite();
        }
        else {
            SetYellow();
            std::cout << "IN  ";
            SetWhite();
        }

        if (protocol == 6) std::cout << "TCP ";
        else if (protocol == 17) std::cout << "UDP ";
        else std::cout << "IP" << (int)protocol << " ";

        int src_port = 0, dst_port = 0;

        if (protocol == 6 && header->len >= 54) {
            src_port = ntohs(*(u_short*)(pkt_data + 34));
            dst_port = ntohs(*(u_short*)(pkt_data + 36));
        }
        else if (protocol == 17 && header->len >= 42) {
            src_port = ntohs(*(u_short*)(pkt_data + 34));
            dst_port = ntohs(*(u_short*)(pkt_data + 36));
        }

        std::cout << src_ip_str << ":" << src_port << " > " << dst_ip_str << ":" << dst_port;
        std::cout << " " << header->len << "b";

        auto it = dns_cache.find(remote_ip);
        if (it != dns_cache.end()) {
            SetLightBlue();
            std::cout << " [" << it->second << "]";
            SetWhite();
        }

        std::cout << "\n";
        return;
    }

    SetLightBlue();
    std::cout << "\n============================================\n";
    printf("%02d:%02d:%02d.%03d  ", st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
    SetWhite();
    std::cout << "#" << packet_count << "  ";

    if (outgoing) {
        SetGreen();
        std::cout << "ИСХОДЯЩИЙ";
    }
    else {
        SetYellow();
        std::cout << "ВХОДЯЩИЙ";
    }
    SetWhite();
    std::cout << "  " << header->len << " байт";

    int headers_size = 14;
    if (protocol == 6 && header->len >= 54) {
        int ip_len = (pkt_data[14] & 0x0F) * 4;
        int tcp_len = ((pkt_data[14 + ip_len + 12] >> 4) & 0x0F) * 4;
        headers_size = 14 + ip_len + tcp_len;
    }
    else if (protocol == 17 && header->len >= 42) {
        int ip_len = (pkt_data[14] & 0x0F) * 4;
        headers_size = 14 + ip_len + 8;
    }

    SetGray();
    std::cout << " (данные: " << (header->len - headers_size) << " байт)";
    SetWhite();
    std::cout << "\n";

    SetGray();
    std::cout << "  MAC:  ";
    SetWhite();
    for (int i = 0; i < 6; i++) printf("%02X", pkt_data[i + 6]);
    std::cout << " > ";
    for (int i = 0; i < 6; i++) printf("%02X", pkt_data[i]);
    std::cout << "\n";

    int src_port = 0, dst_port = 0;

    if (protocol == 6 && header->len >= 54) {
        src_port = ntohs(*(u_short*)(pkt_data + 34));
        dst_port = ntohs(*(u_short*)(pkt_data + 36));
    }
    else if (protocol == 17 && header->len >= 42) {
        src_port = ntohs(*(u_short*)(pkt_data + 34));
        dst_port = ntohs(*(u_short*)(pkt_data + 36));
    }

    std::cout << "  IP:   " << src_ip_str << ":" << src_port;
    SetLightBlue();
    std::cout << " > ";
    SetWhite();
    std::cout << dst_ip_str << ":" << dst_port << "\n";

    std::string proto_name;
    if (protocol == 6) proto_name = "TCP";
    else if (protocol == 17) proto_name = "UDP";
    else proto_name = "IP-" + std::to_string((int)protocol);

    int service_port = outgoing ? dst_port : src_port;
    std::string service = GetProtocolByPort(service_port);

    std::cout << "  Прот:  " << proto_name;
    if (!service.empty()) {
        SetLightBlue();
        std::cout << " (" << service << ")";
        SetWhite();
    }
    std::cout << "\n";

    auto it = dns_cache.find(remote_ip);
    if (it != dns_cache.end()) {
        std::cout << "  Домен: ";
        SetLightBlue();
        std::cout << it->second;
        SetWhite();
    }

    std::string geo = GetCountryAndProvider(remote_ip);
    if (!geo.empty()) {
        std::cout << "  " << geo;
    }

    if (it != dns_cache.end() || !geo.empty()) {
        std::cout << "\n";
    }

    std::string os = GetOSByTTL(ttl);
    if (!os.empty()) {
        SetGray();
        std::cout << "  TTL:   " << (int)ttl << " (" << os << ")\n";
        SetWhite();
    }

    if (protocol == 6 && header->len >= 54) {
        u_char flags = pkt_data[14 + ((pkt_data[14] & 0x0F) * 4) + 13];
        std::cout << "  Флаги: ";
        if (flags & 0x02) { SetLightBlue(); std::cout << "SYN "; SetWhite(); }
        if (flags & 0x10) { SetGreen(); std::cout << "ACK "; SetWhite(); }
        if (flags & 0x01) { SetRed(); std::cout << "FIN "; SetWhite(); }
        if (flags & 0x04) { SetYellow(); std::cout << "RST "; SetWhite(); }
        if (flags & 0x08) { SetGray(); std::cout << "PSH "; SetWhite(); }
        std::cout << "\n";
    }

    if (protocol == 6 && outgoing) {
        std::string process = GetProcessByPort(src_port, true);
        if (!process.empty()) {
            SetGray();
            std::cout << "  Проц:  " << process << "\n";
            SetWhite();
        }
    }

    int packets_from_ip = ip_packet_count[remote_ip];
    int bytes_from_ip = ip_byte_count[remote_ip];

    SetGray();
    std::cout << "  Стат:  пакетов от этого IP: " << packets_from_ip;
    std::cout << " | трафик: ";
    SetWhite();

    if (bytes_from_ip > 1048576) {
        printf("%.1f МБ", bytes_from_ip / 1048576.0);
    }
    else if (bytes_from_ip > 1024) {
        printf("%.1f КБ", bytes_from_ip / 1024.0);
    }
    else {
        std::cout << bytes_from_ip << " Б";
    }

    SetLightBlue();
    std::cout << "\n============================================\n\n";
    SetWhite();
}

DWORD WINAPI CaptureThread(LPVOID lpParam) {
    pcap_t* handle = (pcap_t*)lpParam;
    global_handle = handle;

    while (running) {
        if (!paused) {
            pcap_dispatch(handle, -1, packet_handler, nullptr);
        }
        Sleep(1);
    }

    return 0;
}

pcap_if_t* FindMainAdapter(pcap_if_t* alldevs) {
    pcap_if_t* device = alldevs;

    while (device) {
        std::string desc = device->description ? device->description : "";

        if (desc.find("WAN Miniport") != std::string::npos ||
            desc.find("Loopback") != std::string::npos ||
            desc.find("Virtual") != std::string::npos ||
            desc.find("Bluetooth") != std::string::npos ||
            desc.find("Teredo") != std::string::npos ||
            desc.find("ISATAP") != std::string::npos ||
            desc.find("Tunnel") != std::string::npos) {
            device = device->next;
            continue;
        }

        pcap_addr_t* addr = device->addresses;
        while (addr) {
            if (addr->addr && addr->addr->sa_family == AF_INET) {
                return device;
            }
            addr = addr->next;
        }

        device = device->next;
    }

    return alldevs;
}

int main() {
    SetConsoleCP(1251);
    SetConsoleOutputCP(1251);

    hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    HideCursor();

    pcap_if_t* alldevs;
    char errbuf[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        SetRed();
        std::cout << "Ошибка: " << errbuf << "\n";
        SetWhite();
        system("pause");
        return 1;
    }

    pcap_if_t* device = FindMainAdapter(alldevs);

    if (!device) {
        std::cout << "Адаптеры не найдены\n";
        pcap_freealldevs(alldevs);
        system("pause");
        return 1;
    }

    bool exit_program = false;

    while (!exit_program) {
        target_ips.clear();
        dns_cache.clear();
        ip_packet_count.clear();
        ip_byte_count.clear();
        packet_count = 0;
        monitor_specific_domain = false;

        pcap_t* handle = pcap_open_live(device->name, 65536, 1, 1, errbuf);

        if (!handle) {
            SetRed();
            std::cout << "Ошибка: " << errbuf << "\nЗапустите от Администратора\n";
            SetWhite();
            pcap_freealldevs(alldevs);
            system("pause");
            return 1;
        }

        std::vector<std::string> modes = {
            "Весь трафик",
            "Определенный домен",
            "Только TCP",
            "Только UDP",
            "HTTP и HTTPS",
            "DNS запросы"
        };

        std::vector<std::string> filter_strings = {
            "",
            "",
            "tcp",
            "udp",
            "tcp port 80 or tcp port 443 or tcp port 8080",
            "udp port 53"
        };

        system("cls");

        SetLightBlue();
        std::cout << "Адаптер: ";
        SetWhite();
        std::cout << (device->description ? device->description : "Неизвестно") << "\n";

        std::cout << "\n";

        CONSOLE_SCREEN_BUFFER_INFO csbi;
        GetConsoleScreenBufferInfo(hConsole, &csbi);
        int menu_start = csbi.dwCursorPosition.Y;

        int choice = ShowMenu(modes, "ВЫБОР РЕЖИМА", menu_start);

        if (choice == -1) {
            pcap_close(handle);
            exit_program = true;
            break;
        }

        if (choice == 1) {
            system("cls");
            SetLightBlue();
            std::cout << "Введите домен: ";
            SetWhite();
            std::cin >> target_domain;
            monitor_specific_domain = true;
        }

        if (!monitor_specific_domain && !filter_strings[choice].empty()) {
            struct bpf_program fcode;
            if (pcap_compile(handle, &fcode, filter_strings[choice].c_str(), 1, PCAP_NETMASK_UNKNOWN) != -1) {
                pcap_setfilter(handle, &fcode);
                pcap_freecode(&fcode);
            }
        }

        system("cls");

        SetLightBlue();
        std::cout << "Адаптер: ";
        SetWhite();
        std::cout << (device->description ? device->description : "Неизвестно") << "\n";

        SetLightBlue();
        std::cout << "Режим: ";
        SetWhite();
        std::cout << modes[choice];

        if (monitor_specific_domain) {
            std::cout << " (" << target_domain << ")";
        }

        std::cout << "\n";

        SetGray();
        std::cout << "ПРОБЕЛ - пауза | TAB - компактный режим | ESC - назад в меню\n\n";
        SetWhite();

        running = true;
        paused = false;
        return_to_menu = false;

        HANDLE hThread = CreateThread(NULL, 0, CaptureThread, handle, 0, NULL);

        while (running) {
            if (_kbhit()) {
                int key = _getch();
                switch (key) {
                case 27: // ESC - возврат в меню
                    running = false;
                    return_to_menu = true;
                    pcap_breakloop(handle);
                    break;
                case 32: // ПРОБЕЛ - пауза
                    paused = !paused;
                    break;
                case 9: // TAB - смена режима
                    detailed_mode = !detailed_mode;
                    if (detailed_mode) {
                        SetGreen();
                        std::cout << "\n[ПОДРОБНЫЙ РЕЖИМ]\n\n";
                        SetWhite();
                    }
                    else {
                        SetGreen();
                        std::cout << "\n[КОМПАКТНЫЙ РЕЖИМ]\n\n";
                        SetWhite();
                    }
                    break;
                }
            }
            Sleep(10);
        }

        WaitForSingleObject(hThread, 2000);
        CloseHandle(hThread);
        pcap_close(handle);

        if (!return_to_menu) {
            exit_program = true;
        }
    }

    pcap_freealldevs(alldevs);

    return 0;
}