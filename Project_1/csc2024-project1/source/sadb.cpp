#include "sadb.h"

#include <arpa/inet.h>
#include <unistd.h>

#include <iomanip>
#include <iostream>

std::optional<ESPConfig> getConfigFromSADB() {
  // Allocate buffer
  std::vector<uint8_t> message(65536);
  sadb_msg msg{};
  // TODO: Fill sadb_msg
  msg.sadb_msg_version = PF_KEY_V2;
  msg.sadb_msg_type = SADB_DUMP;
  msg.sadb_msg_satype = SADB_SATYPE_ESP;
  msg.sadb_msg_len = sizeof(msg) / 8; // sadb_msg_len的单位是8 byte
  msg.sadb_msg_pid =  getpid();

  // TODO: Create a PF_KEY_V2 socket and write msg to it
  int write_socket = socket(PF_KEY, SOCK_RAW, PF_KEY_V2);
  checkError(write_socket, "create socket error");
  checkError(write(write_socket, &msg, sizeof(msg)), "write msg error");
  // Then read from socket to get SADB information
  int message_length = 0;
  struct sadb_msg* sadb_info;
  struct sadb_ext* ext_header;
  struct sadb_sa* sa;
  struct sadb_key* sadbkey;
  std::vector<uint8_t> key;
  struct sadb_address *addr;
  struct sockaddr_in *source_addr, *destination_addr;
  bool sadb_EOF = false;
  while(!sadb_EOF)
  {
    // message.data()指向数组中第一个元素的指针(C++11的用法)，等同&message[0]
    message_length = read(write_socket, message.data(), message.size());
    checkError(message_length, "read socket error");
    // 透過將message強制轉型成sadb_msg來取得sadb_msg的參數
    sadb_info = (struct sadb_msg*) &message[0];
    if(sadb_info->sadb_msg_errno != 0)
    {
      printf("sadb error number %s\n", strerror(sadb_info->sadb_msg_errno));
      exit(1);
    }
    
    int current_position = sizeof(struct sadb_msg);
    while(current_position < message_length)
    {
      // 透過強制轉型成sadb_ext來取得參數，剩下沒用到的不管
      // ext_header只吃可以吃的，message原來的資料不受影響
      ext_header = (struct sadb_ext *)(&message[0]+current_position);
      int type = ext_header->sadb_ext_type;
      switch(type)
      {
        case SADB_EXT_SA: //1 裡面有sadb_sa_spi, sadb_sa_auth, sadb_sa_encrypt
        {
          sa = (struct sadb_sa *)(&message[0]+current_position);
          break;
        }
        case SADB_EXT_KEY_AUTH:// 8
        {
          // 一樣強制轉型
          sadbkey = (struct sadb_key *)(&message[0]+current_position);
          key.clear();
          int key_size = (sadbkey->sadb_key_bits)/8; //bits to bytes
          key.resize(key_size);
          memcpy(&key[0], &message[current_position]+sizeof(struct sadb_key), key_size);
          break;
        }
        case SADB_EXT_ADDRESS_SRC:// 5
        {
          addr = (struct sadb_address *)(&message[0]+current_position);
          source_addr = (struct sockaddr_in *)(addr + 1);
          break;
        }
        case SADB_EXT_ADDRESS_DST:// 6
        {
          addr = (struct sadb_address *)(&message[0]+current_position);
          destination_addr = (struct sockaddr_in *)(addr + 1);
          break;
        }
        default:
          break;
      }
      // sadb_ext_len 單位是 8 bytes
      // current_position換到下一個sadb_ext區塊
      current_position += (ext_header->sadb_ext_len)*8;
    }
    
    if(sadb_info->sadb_msg_seq == 0)// reach the end
      sadb_EOF = true;
  }
  close(write_socket);
  
  // TODO: Set size to number of bytes in response message
  int size = message_length;

  // Has SADB entry
  if (size != sizeof(sadb_msg)) {
    ESPConfig config{};
    // TODO: Parse SADB message
    config.spi = sa->sadb_sa_spi;
    // AALG的encrypt是指計算ESP Auth
    config.aalg = std::make_unique<ESP_AALG>((int)sa->sadb_sa_auth, std::span<uint8_t>{key});
    // EALG的encrypt是指加密
    if((int)sa->sadb_sa_encrypt != SADB_EALG_NONE) // Have enc algorithm:
      config.ealg = std::make_unique<ESP_EALG>((int)sa->sadb_sa_encrypt, std::span<uint8_t>{key});
    else // No enc algorithm:
      config.ealg = std::make_unique<ESP_EALG>(SADB_EALG_NONE, std::span<uint8_t>{});
    // Source address:
    config.local = ipToString(source_addr->sin_addr.s_addr);
    // Destination address:
    config.remote = ipToString(destination_addr->sin_addr.s_addr);
    return config;
  }
  std::cerr << "SADB entry not found." << std::endl;
  return std::nullopt;
}

std::ostream &operator<<(std::ostream &os, const ESPConfig &config) {
  os << "------------------------------------------------------------" << std::endl;
  os << "AALG  : ";
  if (!config.aalg->empty()) {
    os << std::left << std::setw(30) << std::setfill(' ') << config.aalg->name();
    os << "HWACCEL: " << config.aalg->provider() << std::endl;
  } else {
    os << "NONE" << std::endl;
  }
  os << "EALG  : ";
  if (!config.ealg->empty()) {
    os << std::left << std::setw(30) << std::setfill(' ') << config.ealg->name();
    os << "HWACCEL: " << config.aalg->provider() << std::endl;
  } else {
    os << "NONE" << std::endl;
  }
  os << "Local : " << config.local << std::endl;
  os << "Remote: " << config.remote << std::endl;
  os << "------------------------------------------------------------";
  return os;
}