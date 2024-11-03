#include <stdio.h>
#include <libyang/libyang.h>

int main() {
    struct ly_ctx *ctx = NULL;
    struct lys_module *module = NULL;  
    struct lyd_node *data_tree = NULL;
    const char *yang_data = "<capabilities xmlns=\"urn:ietf:params:xml:ns:yang:example\">"
                            "  <receiver-capabilities>"
                            "    <receiver-capability>urn:ietf:capability:https-notif-receiver:encoding:json</receiver-capability>"
                            "  </receiver-capabilities>"
                            "  <receiver-capabilities>"
                            "    <receiver-capability>urn:ietf:capability:https-notif-receiver:encoding:xml</receiver-capability>"
                            "  </receiver-capabilities>"
                            "  <receiver-capabilities>"
                            "    <receiver-capability>urn:ietf:capability:https-notif-receiver:sub-notif</receiver-capability>"
                            "  </receiver-capabilities>"
                            "</capabilities>";

    if (ly_ctx_new(NULL, 0, &ctx) != LY_SUCCESS) {
        printf("Failed to create libyang context\n");
        return 1;
    }

   
    if (lys_parse_path(ctx, "example.yang", LYS_IN_YANG, &module) != LY_SUCCESS) {
        printf("Failed to load module\n");
        ly_ctx_destroy(ctx);
        return 1;
    }


    if (lyd_parse_data_mem(ctx, yang_data, LYD_XML, LYD_PARSE_STRICT | LYD_PARSE_ONLY, 0, &data_tree) != LY_SUCCESS) {
        printf("Failed to parse data\n");
        ly_ctx_destroy(ctx);
        return 1;
    }

    printf("Data is valid per YANG schema\n");

    lyd_free_all(data_tree);
    ly_ctx_destroy(ctx);

    return 0;
}
