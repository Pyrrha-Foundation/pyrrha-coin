# Libnexa

## Libnexa v2 API Notable changes and design rationale:

1. The C language does not have function overloads. To make a v2 of the API the naming scheme needed to be changed from camelCase to lower_case_with_underscores to avoid function redeclaration errors with the v1 api. All functions now use lower_case_with_underscores.

2. Rather than editing buffers passed in as args, when buffers need to be returned they are allocated in the API call and must be freed using the `libnexa_free` API call.

3. Because buffers are allocated internally, the resultLen param always describes the size of the buffer returned. To get the specific errors you must use the `get_libnexa_error` or `get_libnexa_error_string` api calls.

4. API params must be const when possible. If a param is not const it signifies that it is going to be edited in the API call and the value should be checked upon return. If the API return type is an array, the first non-const param must always be resultLen which will hold the length of the array upon return.

5. JVM reliant languages use JNI wrappers to have a foreign function interface with C/C++. JNI has a more limited expression of primitive data type values due to the lack of unsigned primitive data types. To compensate for this all byte array lengths in libnexa use uint32_t which always has a value representable by at least a jlong while still keeping the correctness than an array can not have a negative length. It is recommended that future JNI API wrappers use jlong for all byte array lengths. Converting the existing JNI API wrappers is not necessary because all current functions should never return an array with a size greater than or equal to 0x80000000 unless it is in error.

6. Fixed length ints are now used where possible.

7. All API that have a char\* return type return a null terminating array. API with uint8_t\* return type are not null terminating.

8. In v1 `verifyMessage` returned a positive or negative size indicative of whether or not the passed in pubkey hash matched the recovered hash in the signature and wrote the recovered pubkey to the result arg. In v2 `verify_message` returns a boolean rather than editing a buffer. To get the pubkey from a message, the `recover_pubkey_from_signature` API must be used.
