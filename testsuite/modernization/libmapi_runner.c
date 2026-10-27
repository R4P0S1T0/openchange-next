/* Run the existing library suites without building the server modules. */
#include "testsuite.h"

int main(void)
{
    SRunner *runner = srunner_create(libmapi_property_suite());
    int failed;
    srunner_add_suite(runner, libmapi_idset_suite());
    srunner_run_all(runner, CK_NORMAL);
    failed = srunner_ntests_failed(runner);
    srunner_free(runner);
    return failed ? 1 : 0;
}
