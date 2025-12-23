#include "wispers_connect.h"
#include <stdio.h>
#include <string.h>

int main(void) {
    WispersNodeStateManagerHandle *manager = wispers_in_memory_manager_new();
    if (!manager) {
        fprintf(stderr, "failed to init manager\n");
        return 1;
    }

    WispersPendingNodeStateHandle *pending = NULL;
    WispersRegisteredNodeStateHandle *registered = NULL;
    WispersStatus status = wispers_manager_restore_or_init(
        manager,
        "app.example",
        NULL,
        &pending,
        &registered
    );

    if (status != WISPERS_STATUS_SUCCESS) {
        fprintf(stderr, "restore/init failed: %d\n", status);
        wispers_manager_free(manager);
        return 1;
    }

    if (registered) {
        printf("already registered\n");
        wispers_registered_state_free(registered);
    } else if (pending) {
        char *url = wispers_pending_state_registration_url(pending, "https://wispers.dev/add-node");
        printf("Registration URL: %s\n", url);
        wispers_string_free(url);

        status = wispers_pending_state_complete_registration(
            pending,
            "connectivity-group",
            "node-123",
            &registered
        );

        if (status != WISPERS_STATUS_SUCCESS) {
            fprintf(stderr, "complete_registration failed: %d\n", status);
            wispers_manager_free(manager);
            return 1;
        }

        printf("Registration complete!\n");
        wispers_registered_state_free(registered);
    }

    wispers_manager_free(manager);
    return 0;
}
