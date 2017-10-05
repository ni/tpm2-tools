tpm2_nvread 1 "SEPTEMBER 2017" tpm2-tools
==================================================

NAME
----

tpm2_nvread(1) - Read the data stored in a Non-Volatile (NV)s index.

SYNOPSIS
--------

`tpm2_nvread` [OPTIONS]

DESCRIPTION
-----------

tpm2_nvread(1) - Read the data stored in a Non-Volatile (NV)s index.

OPTIONS
-------

  * `-x`, `--index`=_NV\_INDEX_:
    Specifies the index to define the space at.

  * `-a`, `--authHandle`=_SECRET\_DATA\_FILE_:
    specifies the handle used to authorize:
    * `0x40000001` for `TPM_RH_OWNER`
    * `0x4000000C` for `TPM_RH_PLATFORM`

  * `-f`, `--output`=_FILE\:
    file to write data

  * `-P`, `--handlePasswd`=_HANDLE\_PASSWORD_:
    specifies the password of authHandle. Passwords should follow the
    "password formatting standards, see section "Password Formatting".

  * `-s`, `--size`=_SIZE_:
    Specifies the size of data to be read in bytes, starting from 0 if
    offset is not specified. If not specified, the size of the data
    as reported by the public portion of the index will be used.

  * `-o`, `--offset`=_OFFSET_:
    The offset within the NV index to start reading from.

  * `-S`, `--input-session-handle`=_SIZE_:
    Optional Input session handle from a policy session for authorization.

[common options](common/options.md)

[common tcti options](common/tcti.md)

[password formatting](common/password.md)

EXAMPLES
--------

To read 32 bytes from an index starting at offset 0:

```
tpm2_nvread -x 0x1500016 -a 0x40000001 -s 32
```

RETURNS
-------
0 on success or 1 on failure.

BUGS
----
[Github Issues](https://github.com/01org/tpm2-tools/issues)

HELP
----
See the [Mailing List](https://lists.01.org/mailman/listinfo/tpm2)
