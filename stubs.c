/* Minimal stubs for symbols that live in other DSCO translation units.
 * Only what the capability gate + surface_policy reference at link time.
 * These do not affect the code paths under test (bash/git/control). */
#include <stdbool.h>
#include <stddef.h>

bool tools_meta_is_read_only(const char *name) { (void)name; return false; }
bool native_windows_sensitive(const char *name, const char *input) { (void)name; (void)input; return false; }
bool buffer_store_sensitive(const char *input) { (void)input; return false; }
