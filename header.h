#pragma once
#ifndef HEADER_H
#define HEADER_H
#include <iostream>
#include <map>
#include <pcap.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <cmath>
#include <vector>
#include <unistd.h>
#include <stdlib.h>

using namespace std;

#pragma pack(push,1)
struct radiotap_header {
        u_int8_t        it_version;     /* set to 0 */
        u_int8_t        it_pad;
        u_int16_t       it_len;         /* entire length */
        u_int32_t       it_present;     /* fields present */
} __attribute__((__packed__));

struct beacon_frame {
    uint16_t type;
    uint16_t duration;
    uint8_t dmac[6];
    uint8_t smac[6];
    uint8_t bssid[6];
    uint16_t seq;
};

struct wireless {
    uint16_t code;
};

struct beacon_fixed {
    uint8_t timestamp[8];
    uint16_t interval;
    uint16_t capab;
};

struct ssid{
    uint8_t ssid_num;
    uint8_t ssid_len;
    vector<uint8_t> essid;
    uint8_t essid_len;
};

struct deauth {
    struct radiotap_header radio;
    struct beacon_frame beacon;
    struct wireless wm;
};

#pragma pack(pop)

#endif // HEADER_H
