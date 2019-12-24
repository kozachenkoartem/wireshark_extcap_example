#include "config.h"
#include <gmodule.h>
/* plugins are DLLs */
#define WS_BUILD_DLL
#include "ws_symbol_export.h"
#include <epan/proto.h>

void proto_register_example(void);
void proto_reg_handoff_example(void);

WS_DLL_PUBLIC_DEF const gchar plugin_version[] = "0.0.1";
WS_DLL_PUBLIC_DEF const int plugin_want_major = VERSION_MAJOR;
WS_DLL_PUBLIC_DEF const int plugin_want_minor = VERSION_MINOR;
WS_DLL_PUBLIC void plugin_register(void);

void plugin_register(void)
{
    static proto_plugin plugin = {.register_protoinfo = proto_register_example,
                                  .register_handoff = proto_reg_handoff_example};
    proto_register_plugin(&plugin);
}
