#include "ws_symbol_export.h"
#include "dissector.h"
#include <epan/packet.h>
#include <iostream>
#include <string>
#include <sstream>
#include <iomanip>
#include <epan/prefs.h>

#define ADD_NODE(x) { &(x).id,\
{ (x).name, (x).abbrev,  \
    (x).type, (x).display, \
    (x).strings, (x).mask, \
    NULL, HFILL }}

static int dissect_proto(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_);

struct dissect_node {
    const char *name = nullptr;
    const char *abbrev = nullptr;
    ftenum type = {FT_BYTES};
    int display = {BASE_HEX};
    const void *strings;
    guint64 mask = {0};
    int id = {-1};
    dissect_node(){}
    dissect_node(const char *name_, const char *abbrev_, ftenum type_,
              int display_, const void *strings_ = nullptr, int mask_ = 0)
        : name(name_),
          abbrev(abbrev_),
          type(type_),
          display(display_),
          strings(strings_),
          mask(mask_){}
};



static int proto_example = -1;
static gint ett_example = -1;

static const value_string ft_val[] = {
    {0x0 , "Request"},
    {0x1 , "Response"},
    {0x2 , "Ack"},
    {0x3 , "Network"},
    {0x4 , "p2p"},
    {0x5 , "read request"},
    {0, NULL}
};


static dissect_node hf_l1       ("Layer #1",   "example.l1",            FT_NONE,  BASE_NONE);
static dissect_node hf_l2       ("Layer #2",   "example.l1",            FT_NONE,  BASE_NONE);
static dissect_node hf_l1_hdr   ("header",     "example.l1.hdr",       FT_UINT16, BASE_HEX);
static dissect_node hf_l1_ctrl  ("frame ctrl", "example.l1.ctrl",       FT_UINT16, BASE_HEX);
static dissect_node hf_unparsed ("unparsed data", "example.unparsed",FT_BYTES, BASE_NONE);

static dissect_node hf_l1_frame_type  ("frame type",       "example.frame_type",    FT_UINT16, BASE_HEX, VALS(ft_val), 0b1110000000000000);
static dissect_node hf_l1_proto_ver    ("protocol version", "example.proto_version", FT_UINT16, BASE_HEX, nullptr,     0b0001111000000000);
static dissect_node hf_l1_field_1    ("field #1", "example.field_1", FT_UINT16, BASE_HEX, nullptr,                     0b0000000111110000);
static dissect_node hf_l1_field_2    ("field #2", "example.field_1", FT_UINT16, BASE_HEX, nullptr,                     0b0000000000001111);



static const int *l1_ctrl_fields[] = {
    &hf_l1_frame_type.id,
    &hf_l1_proto_ver.id,
    &hf_l1_field_1.id,
    &hf_l1_field_2.id,
    NULL
};

void proto_register_example(void) {

    static gint *ett[] = {&ett_example};
    proto_example = proto_register_protocol("Example Protocol", "EXAMPLE", "example");

    static hf_register_info hf[] = {
        ADD_NODE(hf_l1),
        ADD_NODE(hf_l2),
        //------------------------------------------
        ADD_NODE(hf_l1_ctrl),
        ADD_NODE(hf_l1_hdr),
        ADD_NODE(hf_unparsed),
        ADD_NODE(hf_l1_frame_type),
        ADD_NODE(hf_l1_proto_ver),
        ADD_NODE(hf_l1_field_1),
        ADD_NODE(hf_l1_field_2),
    };
    proto_register_field_array(proto_example, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}


void proto_reg_handoff_example(void) {
    static dissector_handle_t handle = create_dissector_handle(dissect_proto, proto_example);
    dissector_add_uint("wtap_encap", WTAP_ENCAP_USER3, handle);
}


static void process_data(tvbuff_t *tvb){
    int pkt_size = tvb_captured_length(tvb);
    u_int8_t pkt_data[pkt_size];
    tvb_memcpy(tvb, pkt_data, 0, pkt_size);

    // processing data...
}

static int dissect_l1(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
    int offset = 0;
    int l_size = 2;

    proto_item *ti = proto_tree_add_item(tree, hf_l1.id, tvb, offset, l_size, FALSE);
    proto_tree *ltree = proto_item_add_subtree(ti, ett_example);

    proto_tree_add_bitmask(ltree, tvb, offset, hf_l1_hdr.id, ett_example, l1_ctrl_fields, ENC_BIG_ENDIAN);


    offset += l_size;
    return offset;
}

static int dissect_l2(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
    int offset = 0;
    int l_size = 5;

    proto_item *ti = proto_tree_add_item(tree, hf_l2.id, tvb, offset, l_size, FALSE);
    proto_tree *ltree = proto_item_add_subtree(ti, ett_example);

    offset += l_size;
    return l_size;
}

static int dissect_proto(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data) {

    int pkt_size = tvb_captured_length(tvb);
    if (!tree){
        return pkt_size;
    }

    if(!pinfo->fd->visited) {
        process_data(tvb);
    }

    int offset = 0;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "EXAMPLE");
    // Add the top header to the protocol tree
    proto_tree *my_tree = proto_item_add_subtree(proto_tree_add_item(tree, proto_example, tvb, 0, pkt_size, FALSE), ett_example);

    // dissect LEVEL #1
    offset += dissect_l1(tvb, pinfo, my_tree);

    // dissect LEVEL #2
    tvbuff_t *next_tvb = tvb_new_subset_length_caplen(tvb, offset, -1, pkt_size - offset);
    offset += dissect_l2(next_tvb, pinfo, my_tree);

    // add unparsed data to the tree
    // we have to process all data in the package
    proto_tree_add_item(my_tree, hf_unparsed.id, tvb, offset, -1, FALSE);
    return pkt_size;
}
