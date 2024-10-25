#include <sysrepo.h>
#include <stdio.h>
#include <string.h>

int main() {
    sr_conn_ctx_t *connection = NULL;
    sr_session_ctx_t *session = NULL;
    sr_val_t *vals = NULL;
    size_t val_count = 0;
    int rc = SR_ERR_OK;

    // Connect to sysrepo
    rc = sr_connect(0, &connection);
    if (rc != SR_ERR_OK) {
        printf("Error by sr_connect: %s\n", sr_strerror(rc));
        return rc;
    }

    // Start a session in the running datastore
    rc = sr_session_start(connection, SR_DS_RUNNING, &session);
    if (rc != SR_ERR_OK) {
        printf("Error by sr_session_start: %s\n", sr_strerror(rc));
        goto cleanup;
    }

    // Get system data
    rc = sr_get_items(session, "/example:capabilities/*", 0, 0, &vals, &val_count);
    if (rc != SR_ERR_OK) {
        printf("Error by sr_get_items: %s\n", sr_strerror(rc));
        goto cleanup;
    }

    // Print the retrieved values
    for (size_t i = 0; i < val_count; ++i) {
        printf("Path: %s, Value: %s\n", vals[i].xpath, vals[i].data.string_val);
    }

cleanup:
    sr_disconnect(connection);
    return rc;
}
