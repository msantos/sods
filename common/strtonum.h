#ifndef HAVE_STRTONUM
long long strtonum(const char *numstr, long long minval, long long maxval,
                   const char **errstrp);
#endif
