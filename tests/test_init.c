#include "wt.h"
#include <assert.h>
#include <stdio.h>

int test_init_cleanup(void)
{
    printf("Testing library initialization and cleanup...\n");

    // Test multiple init/cleanup cycles
    for (int i = 0; i < 3; i++) {
        wt_result_t result = wt_init();
        if (result != WT_SUCCESS) {
            printf("Failed to initialize library (iteration %d): %s\n",
                i, wt_error_string(result));
            return 1;
        }

        // Test version string
        const char* version = wt_get_version();
        if (!version || strlen(version) == 0) {
            printf("Invalid version string\n");
            return 1;
        }
        printf("Library version: %s\n", version);

        // Test error string function
        const char* error_str = wt_error_string(WT_SUCCESS);
        if (!error_str) {
            printf("Error string function failed\n");
            return 1;
        }

        error_str = wt_error_string(WT_ERROR_INVALID_PARAM);
        if (!error_str) {
            printf("Error string function failed for error code\n");
            return 1;
        }

        wt_cleanup();
    }

    // Test logging functions
    wt_init();
    wt_set_log_level(WT_LOG_LEVEL_DEBUG);
    wt_set_log_level(WT_LOG_LEVEL_INFO);
    wt_set_log_level(WT_LOG_LEVEL_WARNING);
    wt_set_log_level(WT_LOG_LEVEL_ERROR);
    wt_cleanup();

    printf("✅ Library initialization and cleanup tests passed\n");
    return 0;
}