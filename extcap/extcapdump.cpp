#include <iostream>
#include <string>
#include <csignal>
#include <unistd.h>
#include <getopt.h>
#include <fstream>
#include "utils.h"
#include <ctime>
#include <arpa/inet.h>

using std::string;

static bool run_loop = true;

void log(const string &msg) {
    std::ofstream file;
    file.open("/tmp/wslog", std::ios::out | std::ios::app);
    file << msg << std::endl;
}

static void exit_from_loop(int) {
    log("exiting from main loop");
    std::cerr << " exit" << std::endl;
    run_loop = false;
}

struct capture_params{
    string in;
    string out;
    string fifo;
    int interface = 0;
    int channel = 0;
};

enum {
    CTRL_ARG_MESSAGE = 0,
    CTRL_ARG_CHANNEL = 1,
    CTRL_ARG_HELP    = 4,
    CTRL_ARG_LOGGER  = 6,
    CTRL_ARG_NONE    = 255
};

enum {
    CTRL_CMD_INITIALIZED = 0,
    CTRL_CMD_SET         = 1,
    CTRL_CMD_ADD         = 2,
    CTRL_CMD_REMOVE      = 3,
    CTRL_CMD_ENABLE      = 4,
    CTRL_CMD_DISABLE     = 5,
    CTRL_CMD_STATUSBAR   = 6,
    CTRL_CMD_INFORMATION = 7,
    CTRL_CMD_WARNING     = 8,
    CTRL_CMD_ERROR       = 9,
};

enum {
    EXTCAP_OPT_LIST_INTERFACES,
    EXTCAP_OPT_VERSION,
    EXTCAP_OPT_LIST_DLTS,
    EXTCAP_OPT_INTERFACE,
    EXTCAP_OPT_CONFIG,
    EXTCAP_OPT_CTRL_IN,
    EXTCAP_OPT_CTRL_OUT,
    EXTCAP_OPT_FIFO,
    EXTCAP_OPT_CHANNEL,
    EXTCAP_OPT_CAPTURE,
    EXTCAP_OPT_CAPTURE_FILTER,
    EXTCAP_OPT_DEBUG,
    EXTCAP_OPT_DEBUG_FILE,
};

#define LINKTYPE_USER_3 150 // see https://www.tcpdump.org/linktypes.html

static struct option longopts[] = {
{ "extcap-interfaces", no_argument, nullptr, EXTCAP_OPT_LIST_INTERFACES},
{ "extcap-version", optional_argument, nullptr, EXTCAP_OPT_VERSION},
{ "extcap-dlts", no_argument, nullptr, EXTCAP_OPT_LIST_DLTS},
{ "extcap-interface", required_argument, nullptr, EXTCAP_OPT_INTERFACE},
{ "extcap-config", no_argument, nullptr, EXTCAP_OPT_CONFIG},
{ "extcap-control-in", required_argument, nullptr, EXTCAP_OPT_CTRL_IN},
{ "extcap-control-out", required_argument, nullptr, EXTCAP_OPT_CTRL_OUT},
{ "fifo", required_argument, nullptr, EXTCAP_OPT_FIFO},
{ "channel", required_argument, nullptr, EXTCAP_OPT_CHANNEL},
{ "capture", no_argument, nullptr, EXTCAP_OPT_CAPTURE},
{ "extcap-capture-filter", required_argument, nullptr, EXTCAP_OPT_CAPTURE_FILTER},
{ "fifo", required_argument, nullptr, EXTCAP_OPT_FIFO},
{ "debug", no_argument, nullptr, EXTCAP_OPT_DEBUG},
{ "debug-file", required_argument, nullptr, EXTCAP_OPT_DEBUG_FILE},
{ 0, 0, nullptr, 0 }
};

template<typename T>
void write_to_stream(std::ostream &ss, T val){
    ss.write((char*)&val, sizeof(T));
}


void extcap_version(){
    std::cout << "extcap {version=1.0}"
                 "{help=https://github.com/kozachenkoartem/wireshark_extcap_example}"
                 "{display=extcap example interface"
              << std::endl;
}

void extcap_interfaces(){

    extcap_version();

    printf("interface {value=extcap_%d}{display=EXTCAP}\n", 1);
    printf("interface {value=extcap_%d}{display=EXTCAP}\n", 2);

    printf("control {number=%d}{type=selector}{display=Channel}{tooltip=Channel}\n", CTRL_ARG_CHANNEL);
    printf("control {number=%d}{type=string}{display=Raw message}"
           "{tooltip=Package message in hexdecimal format}"
           "{placeholder=Enter the raw package here ...}\n", CTRL_ARG_MESSAGE);
    printf("control {number=%d}{type=button}{role=logger}{display=Log}{tooltip=Show capture log}\n", CTRL_ARG_LOGGER);
    printf("control {number=%d}{type=button}{role=help}{display=Help}{tooltip=Show help}\n", CTRL_ARG_HELP);
    printf("value {control=%d}{value=0}{display=0}{default=true}\n", CTRL_ARG_CHANNEL);

    for (int i = 1; i <= 8; ++i) {
        printf("value {control=%d}{value=%d}{display=%d}\n", CTRL_ARG_CHANNEL, i, i);
    }
}


void extcap_dlts(){
    printf("dlt {number=150}{name=USER3}{display=Example is using USER3}");
}


void write_pcap_header(std::ostream &ss){
    write_to_stream(ss, uint32_t(0xa1b2c3d4));
    write_to_stream(ss, short(2)); // Pcap Major Version
    write_to_stream(ss, short(4)); // Pcap Minor Version
    write_to_stream(ss, uint32_t(0)); // Timezone
    write_to_stream(ss, uint32_t(0)); // Accurancy of timestamps
    write_to_stream(ss, uint32_t(0xffff)); //Max Length of capture frame
    write_to_stream(ss, int(LINKTYPE_USER_3));    // USER_3
    ss.flush();
}

void write_pcap_package(std::ostream &ss, const data_t &pkt){
    if(pkt.empty()) {
        return;
    }
    log("write " + std::to_string(pkt.size()));
    write_to_stream(ss, uint32_t(std::time(nullptr))); // timestamp seconds
    write_to_stream(ss, uint32_t(0));                  // timestamp nanoseconds
    write_to_stream(ss, uint32_t(pkt.size()));         // length captured
    write_to_stream(ss, uint32_t(pkt.size()));         // length in frame

    ss.write(pkt.data(), pkt.size());   // package data
    ss.flush();
}

void control_write(std::ofstream &ss, uint8_t arg, uint8_t type, const string &payload){
    write_to_stream(ss, char('T'));
    write_to_stream(ss, uint8_t(0));
    write_to_stream(ss, htons(payload.length() + 2));
    write_to_stream(ss, uint8_t(arg));
    write_to_stream(ss, uint8_t(type));
    ss.write(payload.data(), payload.size());
    ss.flush();
}

void send_raw_command(std::ofstream &out, const string &msg){

    control_write(out, CTRL_ARG_LOGGER, CTRL_CMD_ADD,
                  "send raw message: " + msg + " \n ");
}

void set_channel(std::ofstream &out, int channel){
    log("set_channel");
    control_write(out, CTRL_ARG_LOGGER, CTRL_CMD_ADD,
                  "set channel: " + std::to_string(channel) + " \n");
}

void extcap_capture(const capture_params& params){

    std::streambuf * buf;
    std::ofstream of;

    if(params.fifo == "-") {
        buf = std::cout.rdbuf();
    } else {
        of.open(params.fifo, std::ios::out | std::ios::binary);
        if(!of.is_open()){
            std::cerr << "cant open file :" << params.fifo << std::endl;
            return;
        }
        buf = of.rdbuf();
    }

    std::ostream fifo(buf);
    write_pcap_header(fifo);

    std::ofstream out;
    std::ifstream in;

    if(!params.in.empty()) {
        in.open(params.in, std::ios::in | std::ios::binary);
        if(!in.is_open()){
            std::cerr << "cant open file :" << params.in << std::endl;
            return;
        }
    }

    if(!params.out.empty()) {
        out.open(params.out, std::ios::out | std::ios::binary);
        if(!out.is_open()) {
            std::cerr << "cant open file :" << params.out << std::endl;
            return;
        }
    }


    log("starting capturing...");

    while(run_loop) {

        write_pcap_package(fifo, from_string("AEB205AEB205AEB205AEB205AEB205AEB205AEB205AEB205AEB205AEB205AEB205AEB205"));
        sleep(1);

    }

    log("exiting from main");
}

int parse_interface(const string& interface_str){
    // skip "extcap_"
    // TODO: do this with proper way
    return stoi(interface_str.substr(7));
}


int main(int argc, char *argv[])
{
    if (argc == 1) {
        std::cerr << "no arguments given" << std::endl;
    }
    int result = 0;
    int option_idx = 0;

    capture_params params;
    bool capture = false;

    while ((result = getopt_long(argc, argv, ":", longopts, &option_idx)) != -1) {
        switch (result) {
        case EXTCAP_OPT_LIST_INTERFACES:
            extcap_interfaces();
            return EXIT_SUCCESS;
        case EXTCAP_OPT_LIST_DLTS:
            extcap_dlts();
            return EXIT_SUCCESS;
        case EXTCAP_OPT_VERSION:
            extcap_version();
            return EXIT_SUCCESS;
        case EXTCAP_OPT_INTERFACE:
            params.interface = parse_interface(optarg);
            break;
        case EXTCAP_OPT_CTRL_IN:
            params.in = string(optarg);
            break;
        case EXTCAP_OPT_CTRL_OUT:
            params.out = string(optarg);
            break;
        case EXTCAP_OPT_FIFO:
            params.fifo = string(optarg);
            break;
        case EXTCAP_OPT_CHANNEL:
            params.channel = stoi(string(optarg));
            break;
        case EXTCAP_OPT_CAPTURE:
            capture = true;
            break;
        }
    }

    if(capture){
        extcap_capture(params);
    }

    return EXIT_SUCCESS;
}
