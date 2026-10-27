openchange-testsuite
======================

Openchange unit tests testsuite utility.
It is using check library for unit testing.

Modernization checks
--------------------

The recovered library tests can run without building the server modules:

    ./autogen.sh
    ./configure --with-samba=/usr
    make check-libmapi-modernization
    make check-mapiproxy-registries

This runs the existing libmapi property/IDSET suites and native NDR request/reply,
array-bound and union-switch regression checks. Python-only tooling checks are:

    python3 -m unittest discover -s testsuite/modernization -v

For the Python runtime tests and isolated SQL database options, see
[the modernization guide](../doc/MODERNIZATION.md).

Usage
-----

Build Openchange as usual. Test suite goes to:

    bin/openchange-testsuite

To run all tests:

    bin/openchange-testsuite

By default, check runs in 'fork mode'. Which makes it hard to debug. To run in 'no-fork mode':

    CK_FORK=no bin/openchange-testsuite

To run just one testsuite or testcase, pass the name of the suite in CK_RUN_SUITE environment
variable or CK_RUN_CASE for a test case respectively:

    CK_RUN_SUITE="libmapistore named properties: interface" bin/openchange-testsuite

or

    CK_RUN_CASE="Interface" bin/openchange-testsuite

To check which tests are run, use `CK_VERBOSITY` environment
variable with `verbose` value as follows:

    CK_VERBOSITY=verbose bin/openchange-testsuite

To review all available options, go to the following link:

    http://check.sourceforge.net/doc/check_html/check_3.html#SRunner-Output

Check for memory leaks
----------------------

To check for memory leaks, run as:

    bin/openchange-testsuite --leak-report

or
    bin/openchange-testsuite --leak-report-full

for more detailed leak report.


----------

**List of "known" memory leaks (coming from Samba)**

 - struct tevent_ops_list
 - struct ldb_hooks
 - struct backends_list_entry
 - struct loaded
 - struct bitmap
 - struct loadparm_context


Enjoy!
