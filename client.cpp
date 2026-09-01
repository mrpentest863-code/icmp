#include <iostream>
#include <thread>
#include <chrono>
#include <atomic>
#include <cstring>
#include <csignal>
#include <vector>
#include <map>
#include <mutex>
#include <netinet/ip_icmp.h>
#include <netinet/ip.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include "pingtunnel.h"

std::atomic<bool> running{true};
std::atomic<int> sequence{0};
int icmp_sock = -1;
sockaddr_in server_addr{};
std::string username, password;
int vpn_fd = -1;

void handle_signal(int) {
    running = false;
}

void send_icmp(const std::string& conn_id, const std::vector<uint8_t>& data, int type) {
    MyMsg msg;
    msg.id = conn_id;
    msg.type = type;
    msg.data = data;
    msg.magic = MyMsg_MAGIC;
    msg.key = 0;
    msg.username = username;
    msg.password = password;

    std::vector<uint8_t> mb = marshalMyMsg(msg);
    size_t total_len = sizeof(struct icmphdr) + mb.size();
    std::vector<uint8_t> packet(total_len);

    struct icmphdr* hdr = reinterpret_cast<struct icmphdr*>(packet.data());
    hdr->type = ICMP_ECHO;
    hdr->code = 0;
    hdr->checksum = 0;
    hdr->un.echo.id = htons(0x1234);
    hdr->un.echo.sequence = htons(static_cast<uint16_t>(sequence.fetch_add(1)));

    std::copy(mb.begin(), mb.end(), packet.begin() + sizeof(struct icmphdr));

    uint32_t sum = 0;
    for (size_t i = 0; i < packet.size(); i += 2) {
        uint16_t word = packet[i];
        if (i + 1 < packet.size()) word = (word << 8) | packet[i + 1];
        sum += word;
    }
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    hdr->checksum = ~static_cast<uint16_t>(sum);

    ssize_t sent = sendto(icmp_sock, packet.data(), packet.size(), 0,
                           reinterpret_cast<struct sockaddr*>(&server_addr), sizeof(server_addr));
    if (sent < 0) {
        perror("sendto");
    }
}

void vpn_to_icmp_loop() {
    std::vector<uint8_t> buffer(4096);
    while (running) {
        ssize_t n = read(vpn_fd, buffer.data(), buffer.size());
        if (n <= 0) {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
            continue;
        }
        std::string conn_id = "vpn"; // identifiant de connexion simplifié
        std::vector<uint8_t> data(buffer.begin(), buffer.begin() + n);
        send_icmp(conn_id, data, MyMsg_DATA);
    }
}

void icmp_to_vpn_loop() {
    std::vector<uint8_t> buffer(4096);
    while (running) {
        sockaddr_in src{};
        socklen_t len = sizeof(src);
        ssize_t n = recvfrom(icmp_sock, buffer.data(), buffer.size(), 0,
                              reinterpret_cast<struct sockaddr*>(&src), &len);
        if (n <= 0) continue;

        // Un socket raw ICMP reçoit TOUT le trafic ICMP de la machine,
        // pas seulement les réponses de notre serveur : on doit vérifier
        // l'expéditeur avant de faire confiance au paquet.
        if (src.sin_addr.s_addr != server_addr.sin_addr.s_addr) continue;

        // recvfrom() inclut l'en-tête IP complet (contrairement à l'envoi,
        // où le noyau l'ajoute automatiquement). Il faut donc le sauter
        // en utilisant sa longueur réelle (IHL), pas une valeur fixe.
        if (static_cast<size_t>(n) < sizeof(struct ip)) continue;
        const struct ip* ip_hdr = reinterpret_cast<const struct ip*>(buffer.data());
        size_t ip_hlen = static_cast<size_t>(ip_hdr->ip_hl) * 4;
        if (ip_hlen < sizeof(struct ip) || static_cast<size_t>(n) < ip_hlen + sizeof(struct icmphdr)) {
            continue;
        }

        const struct icmphdr* icmp_h =
            reinterpret_cast<const struct icmphdr*>(buffer.data() + ip_hlen);

        // On ne traite que les réponses ICMP à notre propre id, pour éviter
        // de confondre notre trafic avec un ping système classique.
        if (icmp_h->type != ICMP_ECHOREPLY) continue;
        if (icmp_h->un.echo.id != htons(0x1234)) continue;

        size_t payload_off = ip_hlen + sizeof(struct icmphdr);
        std::vector<uint8_t> payload(buffer.begin() + payload_off, buffer.begin() + n);

        MyMsg msg;
        if (!unmarshalMyMsg(payload, msg)) continue;
        if (msg.magic != MyMsg_MAGIC) continue;

        if (msg.type == MyMsg_DATA) {
            ssize_t written = write(vpn_fd, msg.data.data(), msg.data.size());
            if (written < 0) {
                perror("write vpn_fd");
            }
        }
    }
}

int main(int argc, char* argv[]) {
    if (argc < 5) {
        std::cerr << "Usage: " << argv[0] << " <server_ip> <user> <pass> <vpn_fd>\n";
        return 1;
    }

    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    server_addr.sin_family = AF_INET;
    if (inet_pton(AF_INET, argv[1], &server_addr.sin_addr) != 1) {
        std::cerr << "Adresse IP invalide: " << argv[1] << "\n";
        return 1;
    }
    username = argv[2];
    password = argv[3];

    try {
        vpn_fd = std::stoi(argv[4]);
    } catch (const std::exception&) {
        std::cerr << "vpn_fd invalide: " << argv[4] << "\n";
        return 1;
    }

    icmp_sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (icmp_sock < 0) {
        perror("socket icmp");
        return 1;
    }

    std::thread t1(vpn_to_icmp_loop);
    std::thread t2(icmp_to_vpn_loop);

    while (running) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }

    // On ferme les fds pour débloquer read()/recvfrom() dans les threads,
    // puis on les rejoint proprement au lieu de les détacher.
    shutdown(icmp_sock, SHUT_RDWR);
    close(icmp_sock);
    close(vpn_fd);

    if (t1.joinable()) t1.join();
    if (t2.joinable()) t2.join();

    return 0;
}
