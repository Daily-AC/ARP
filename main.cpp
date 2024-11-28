#include <iostream>
#include <cstring>
#include <cstdlib>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <net/if.h>
#include <sys/ioctl.h>

// ARP封装结构
#pragma pack(1)
struct ARPHeader {
    uint16_t hw_type;         // 硬件类型 (1: 以太网)
    uint16_t proto_type;      // 协议类型 (0x0800: IPv4)
    uint8_t hw_addr_len;      // 硬件地址长度 (6: MAC地址)
    uint8_t proto_addr_len;   // 协议地址长度 (4: IPv4地址)
    uint16_t opcode;          // 操作码 (1: ARP请求, 2: ARP响应)
    uint8_t src_hw_addr[6];   // 源MAC地址
    uint8_t src_proto_addr[4];// 源IP地址
    uint8_t dst_hw_addr[6];   // 目标MAC地址
    uint8_t dst_proto_addr[4];// 目标IP地址
};
#pragma pack()

// 以太网帧结构
struct EthernetHeader {
    uint8_t dst_mac[6]; // 目标MAC地址
    uint8_t src_mac[6]; // 源MAC地址
    uint16_t ethertype; // EtherType
};

// 创建ARP请求
void createARPRequest(ARPHeader &arp_req, const uint8_t *src_mac, const uint8_t *src_ip, const uint8_t *dst_ip) {
    arp_req.hw_type = htons(1); // 以太网
    arp_req.proto_type = htons(0x0800); // IPv4
    arp_req.hw_addr_len = 6; // MAC地址长度
    arp_req.proto_addr_len = 4; // IPv4地址长度
    arp_req.opcode = htons(1); // ARP请求

    memcpy(arp_req.src_hw_addr, src_mac, 6); // 源MAC地址
    memcpy(arp_req.src_proto_addr, src_ip, 4); // 源IP地址
    memset(arp_req.dst_hw_addr, 0x00, 6); // 目标MAC地址未知
    memcpy(arp_req.dst_proto_addr, dst_ip, 4); // 目标IP地址
}

// 发送ARP请求
void sendARPRequest(int sockfd, const struct sockaddr_ll &device, ARPHeader &arp_req, const uint8_t *src_mac) {
    uint8_t frame[42]; // Ethernet头 (14字节) + ARP头 (28字节)

    // Ethernet头
    memcpy(frame, src_mac, 6); // 目标MAC地址（广播）
    memset(frame + 6, 0xFF, 6); // 源MAC地址（广播）
    frame[12] = 0x08; // EtherType (高字节)
    frame[13] = 0x06; // EtherType (低字节)

    // ARP请求包
    memcpy(frame + 14, &arp_req, sizeof(ARPHeader));

    if (sendto(sockfd, frame, sizeof(frame), 0, (struct sockaddr *)&device, sizeof(device)) <= 0) {
        std::cerr << "Failed to send ARP request" << std::endl;
    } else {
        std::cout << "ARP request sent!" << std::endl;
    }
}

// 解析收到的ARP响应包
void parseARPPacket(uint8_t *packet) {
    ARPHeader *arp_header = reinterpret_cast<ARPHeader *>(packet + 14); // 跳过Ethernet头

    std::cout << "ARP Response:" << std::endl;
    std::cout << "Source MAC: ";
    for (int i = 0; i < 6; i++) {
        printf("%02x:", arp_header->src_hw_addr[i]);
    }
    std::cout << "\nSource IP: " << inet_ntoa(*(struct in_addr *)arp_header->src_proto_addr) << std::endl;
    std::cout << "Destination MAC: ";
    for (int i = 0; i < 6; i++) {
        printf("%02x:", arp_header->dst_hw_addr[i]);
    }
    std::cout << "\nDestination IP: " << inet_ntoa(*(struct in_addr *)arp_header->dst_proto_addr) << std::endl;
}

int main() {
    int sockfd;
    struct sockaddr_ll device;
    struct ifreq ifr;

    // 创建原始套接字
    sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (sockfd < 0) {
        perror("Socket creation failed");
        return 1;
    }

    // 获取网络设备接口
    strncpy(ifr.ifr_name, "eth0", IFNAMSIZ - 1); // 选择网络接口 "eth0"
    if (ioctl(sockfd, SIOCGIFINDEX, &ifr) < 0) {
        perror("Failed to get interface index");
        close(sockfd);
        return 1;
    }

    // 填充设备信息
    memset(&device, 0, sizeof(device));
    device.sll_protocol = htons(ETH_P_ARP);
    device.sll_ifindex = ifr.ifr_ifindex;

    // 源MAC和IP地址
    uint8_t src_mac[6] = {0x00, 0x0c, 0x29, 0xab, 0xcd, 0xef};
    uint8_t src_ip[4] = {192, 168, 1, 10}; // 源IP地址
    uint8_t dst_ip[4] = {192, 168, 1, 1}; // 目标IP地址

    ARPHeader arp_req;
    createARPRequest(arp_req, src_mac, src_ip, dst_ip);

    // 发送ARP请求
    sendARPRequest(sockfd, device, arp_req, src_mac);

    // 接收ARP响应
    uint8_t buffer[42];
    while (true) {
        ssize_t len = recvfrom(sockfd, buffer, sizeof(buffer), 0, nullptr, nullptr);
        if (len > 0) {
            // 只处理ARP响应包
            if (buffer[12] == 0x08 && buffer[13] == 0x06) { // 检查EtherType字段
                parseARPPacket(buffer);
                break;
            }
        }
    }

    close(sockfd);
    return 0;
}
