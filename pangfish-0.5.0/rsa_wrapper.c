#include <Python.h>
#include <time.h>
#include "multipowerrsa.h"

/* Python module for Multi-Power RSA */

typedef struct {
    PyObject_HEAD
    mp_rsa_ctx ctx;
} MPRSAObject;

static void
MPRSA_dealloc(MPRSAObject *self)
{
    mp_rsa_clear(&self->ctx);
    Py_TYPE(self)->tp_free((PyObject *)self);
}

static PyObject *
MPRSA_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
    MPRSAObject *self;
    self = (MPRSAObject *)type->tp_alloc(type, 0);
    if (self != NULL) {
        mp_rsa_init(&self->ctx, 2048, 3); // Default values
    }
    return (PyObject *)self;
}

static int
MPRSA_init(MPRSAObject *self, PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = {"key_size", "b", NULL};
    unsigned int key_size = 2048;
    unsigned int b = 3;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "|II", kwlist, &key_size, &b))
        return -1;
    
    // Re-initialize with user-provided parameters
    mp_rsa_clear(&self->ctx);
    mp_rsa_init(&self->ctx, key_size, b);
    
    return 0;
}

static PyObject *
MPRSA_generate_keys(MPRSAObject *self, PyObject *Py_UNUSED(ignored))
{
    if (mp_rsa_generate_keys(&self->ctx) != 0) {
        PyErr_SetString(PyExc_RuntimeError, "Failed to generate keys");
        return NULL;
    }
    
    PyObject *public_key = NULL;
    PyObject *private_key = NULL;
    PyObject *result = NULL;
    unsigned char *pub_key_bytes = NULL;
    unsigned char *priv_key_bytes = NULL;
    size_t pub_key_len, priv_key_len;
    
    // Export public key
    if (mp_rsa_export_public_key(&self->ctx, &pub_key_bytes, &pub_key_len) != 0) {
        PyErr_SetString(PyExc_RuntimeError, "Failed to export public key");
        goto cleanup;
    }
    
    // Export private key
    if (mp_rsa_export_private_key(&self->ctx, &priv_key_bytes, &priv_key_len) != 0) {
        PyErr_SetString(PyExc_RuntimeError, "Failed to export private key");
        goto cleanup;
    }
    
    // Create Python objects for the keys
    public_key = PyBytes_FromStringAndSize((char *)pub_key_bytes, pub_key_len);
    private_key = PyBytes_FromStringAndSize((char *)priv_key_bytes, priv_key_len);
    
    if (!public_key || !private_key) {
        PyErr_SetString(PyExc_MemoryError, "Failed to create key objects");
        goto cleanup;
    }
    
    // Return tuple of (public_key, private_key)
    result = PyTuple_New(2);
    if (!result) {
        goto cleanup;
    }
    
    PyTuple_SET_ITEM(result, 0, public_key);
    PyTuple_SET_ITEM(result, 1, private_key);
    
    // PyTuple_SET_ITEM steals the reference, so don't decrement
    public_key = NULL;
    private_key = NULL;
    
cleanup:
    if (pub_key_bytes) free(pub_key_bytes);
    if (priv_key_bytes) free(priv_key_bytes);
    Py_XDECREF(public_key);
    Py_XDECREF(private_key);
    
    return result;
}

static PyObject *
MPRSA_encrypt(MPRSAObject *self, PyObject *args, PyObject *kwds)
{
    PyObject *message_obj = NULL;
    PyObject *public_key_obj = NULL;
    static char *kwlist[] = {"message", "public_key", NULL};
    
    if (!PyArg_ParseTupleAndKeywords(args, kwds, "O|O", kwlist, &message_obj, &public_key_obj))
        return NULL;
    
    // Handle message input - could be int, bytes, or string
    mpz_t message;
    mpz_init(message);
    
    if (PyLong_Check(message_obj)) {
        // If message is a Python integer
        PyObject *str_obj = PyObject_Str(message_obj);
        if (!str_obj) {
            mpz_clear(message);
            return NULL;
        }
        const char *str = PyUnicode_AsUTF8(str_obj);
        mpz_set_str(message, str, 10);
        Py_DECREF(str_obj);
    } 
    else if (PyBytes_Check(message_obj)) {
        // If message is bytes
        unsigned char *data = (unsigned char *)PyBytes_AS_STRING(message_obj);
        Py_ssize_t len = PyBytes_GET_SIZE(message_obj);
        
        mpz_import(message, len, 1, 1, 0, 0, data);
    }
    else if (PyUnicode_Check(message_obj)) {
        // If message is a string
        const char *str = PyUnicode_AsUTF8(message_obj);
        mpz_set_str(message, str, 10);
    }
    else {
        PyErr_SetString(PyExc_TypeError, "Message must be an integer, bytes, or string");
        mpz_clear(message);
        return NULL;
    }
    
    // Handle public key if provided
    mp_rsa_ctx temp_ctx;
    mp_rsa_ctx *ctx_to_use = &self->ctx;
    
    if (public_key_obj && public_key_obj != Py_None) {
        if (!PyBytes_Check(public_key_obj)) {
            PyErr_SetString(PyExc_TypeError, "Public key must be bytes");
            mpz_clear(message);
            return NULL;
        }
        
        mp_rsa_init(&temp_ctx, self->ctx.key_size, self->ctx.b);
        int result = mp_rsa_import_public_key(&temp_ctx, 
                                             (unsigned char *)PyBytes_AS_STRING(public_key_obj),
                                             PyBytes_GET_SIZE(public_key_obj));
        
        if (result != 0) {
            PyErr_SetString(PyExc_ValueError, "Invalid public key format");
            mp_rsa_clear(&temp_ctx);
            mpz_clear(message);
            return NULL;
        }
        
        ctx_to_use = &temp_ctx;
    }
    
    // Encrypt the message
    mpz_t cipher;
    mpz_init(cipher);
    
    if (mp_rsa_encrypt(ctx_to_use, message, cipher) != 0) {
        PyErr_SetString(PyExc_ValueError, "Encryption failed");
        if (public_key_obj && public_key_obj != Py_None) {
            mp_rsa_clear(&temp_ctx);
        }
        mpz_clear(message);
        mpz_clear(cipher);
        return NULL;
    }
    
    // Convert cipher to string and create Python object
    char *cipher_str = mpz_get_str(NULL, 10, cipher);
    PyObject *result = PyUnicode_FromString(cipher_str);
    
    // Clean up
    free(cipher_str);
    mpz_clear(message);
    mpz_clear(cipher);
    if (public_key_obj && public_key_obj != Py_None) {
        mp_rsa_clear(&temp_ctx);
    }
    
    return result;
}

static PyObject *
MPRSA_decrypt(MPRSAObject *self, PyObject *args, PyObject *kwds)
{
    PyObject *cipher_obj = NULL;
    PyObject *private_key_obj = NULL;
    static char *kwlist[] = {"cipher", "private_key", NULL};
    
    if (!PyArg_ParseTupleAndKeywords(args, kwds, "O|O", kwlist, &cipher_obj, &private_key_obj))
        return NULL;
    
    // Handle cipher input - should be string representing integer
    mpz_t cipher;
    mpz_init(cipher);
    
    if (PyUnicode_Check(cipher_obj)) {
        const char *str = PyUnicode_AsUTF8(cipher_obj);
        mpz_set_str(cipher, str, 10);
    }
    else if (PyLong_Check(cipher_obj)) {
        PyObject *str_obj = PyObject_Str(cipher_obj);
        if (!str_obj) {
            mpz_clear(cipher);
            return NULL;
        }
        const char *str = PyUnicode_AsUTF8(str_obj);
        mpz_set_str(cipher, str, 10);
        Py_DECREF(str_obj);
    }
    else {
        PyErr_SetString(PyExc_TypeError, "Cipher must be a string or integer");
        mpz_clear(cipher);
        return NULL;
    }
    
    // Handle private key if provided
    mp_rsa_ctx temp_ctx;
    mp_rsa_ctx *ctx_to_use = &self->ctx;
    
    if (private_key_obj && private_key_obj != Py_None) {
        if (!PyBytes_Check(private_key_obj)) {
            PyErr_SetString(PyExc_TypeError, "Private key must be bytes");
            mpz_clear(cipher);
            return NULL;
        }
        
        mp_rsa_init(&temp_ctx, self->ctx.key_size, self->ctx.b);
        int result = mp_rsa_import_private_key(&temp_ctx, 
                                              (unsigned char *)PyBytes_AS_STRING(private_key_obj),
                                              PyBytes_GET_SIZE(private_key_obj));
        
        if (result != 0) {
            PyErr_SetString(PyExc_ValueError, "Invalid private key format");
            mp_rsa_clear(&temp_ctx);
            mpz_clear(cipher);
            return NULL;
        }
        
        ctx_to_use = &temp_ctx;
    }
    
    // Decrypt the cipher
    mpz_t message;
    mpz_init(message);
    
    if (mp_rsa_decrypt(ctx_to_use, cipher, message) != 0) {
        PyErr_SetString(PyExc_ValueError, "Decryption failed");
        if (private_key_obj && private_key_obj != Py_None) {
            mp_rsa_clear(&temp_ctx);
        }
        mpz_clear(cipher);
        mpz_clear(message);
        return NULL;
    }
    
    // Result can be returned as integer or bytes
    // Default to integer since RSA typically works with integers
    PyObject *result = NULL;
    char *message_str = mpz_get_str(NULL, 10, message);
    result = PyLong_FromString(message_str, NULL, 10);
    
    // Clean up
    free(message_str);
    mpz_clear(cipher);
    mpz_clear(message);
    if (private_key_obj && private_key_obj != Py_None) {
        mp_rsa_clear(&temp_ctx);
    }
    
    return result;
}

/* Forward declaration for the method table */
static PyObject *MPRSA_decrypt_to_bytes(MPRSAObject *self, PyObject *args, PyObject *kwds);

static PyMethodDef MPRSA_methods[] = {
    {"generate_keys", (PyCFunction)MPRSA_generate_keys, METH_NOARGS,
     "Generate a new Multi-Power RSA key pair"},
    {"encrypt", (PyCFunction)MPRSA_encrypt, METH_VARARGS | METH_KEYWORDS,
     "Encrypt a message using the public key"},
    {"decrypt", (PyCFunction)MPRSA_decrypt, METH_VARARGS | METH_KEYWORDS,
     "Decrypt a message using the private key and return as integer"},
    {"decrypt_to_bytes", (PyCFunction)MPRSA_decrypt_to_bytes, METH_VARARGS | METH_KEYWORDS,
     "Decrypt a message using the private key and return as bytes"},
    {NULL}  /* Sentinel */
};

static PyTypeObject MPRSAType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    .tp_name = "pangfish.MPRSA",
    .tp_doc = "Multi-Power RSA encryption implementation",
    .tp_basicsize = sizeof(MPRSAObject),
    .tp_itemsize = 0,
    .tp_flags = Py_TPFLAGS_DEFAULT,
    .tp_new = MPRSA_new,
    .tp_init = (initproc)MPRSA_init,
    .tp_dealloc = (destructor)MPRSA_dealloc,
    .tp_methods = MPRSA_methods,
};

static PyModuleDef multipowerrsamodule = {
    PyModuleDef_HEAD_INIT,
    .m_name = "_multipowerrsa",
    .m_doc = "Multi-Power RSA encryption module implemented in C",
    .m_size = -1,
};

PyMODINIT_FUNC
PyInit__multipowerrsa(void)
{
    PyObject *m;
    
    if (PyType_Ready(&MPRSAType) < 0)
        return NULL;

    m = PyModule_Create(&multipowerrsamodule);
    if (m == NULL)
        return NULL;

    Py_INCREF(&MPRSAType);
    if (PyModule_AddObject(m, "MPRSA", (PyObject *)&MPRSAType) < 0) {
        Py_DECREF(&MPRSAType);
        Py_DECREF(m);
        return NULL;
    }

    return m;
}

/* Implementation of the decrypt_to_bytes function */
static PyObject *
MPRSA_decrypt_to_bytes(MPRSAObject *self, PyObject *args, PyObject *kwds)
{
    PyObject *cipher_obj = NULL;
    PyObject *private_key_obj = NULL;
    static char *kwlist[] = {"cipher", "private_key", NULL};
    
    if (!PyArg_ParseTupleAndKeywords(args, kwds, "O|O", kwlist, &cipher_obj, &private_key_obj))
        return NULL;
    
    // Handle cipher input - should be string representing integer
    mpz_t cipher;
    mpz_init(cipher);
    
    if (PyUnicode_Check(cipher_obj)) {
        const char *str = PyUnicode_AsUTF8(cipher_obj);
        mpz_set_str(cipher, str, 10);
    }
    else if (PyLong_Check(cipher_obj)) {
        PyObject *str_obj = PyObject_Str(cipher_obj);
        if (!str_obj) {
            mpz_clear(cipher);
            return NULL;
        }
        const char *str = PyUnicode_AsUTF8(str_obj);
        mpz_set_str(cipher, str, 10);
        Py_DECREF(str_obj);
    }
    else {
        PyErr_SetString(PyExc_TypeError, "Cipher must be a string or integer");
        mpz_clear(cipher);
        return NULL;
    }
    
    // Handle private key if provided
    mp_rsa_ctx temp_ctx;
    mp_rsa_ctx *ctx_to_use = &self->ctx;
    
    if (private_key_obj && private_key_obj != Py_None) {
        if (!PyBytes_Check(private_key_obj)) {
            PyErr_SetString(PyExc_TypeError, "Private key must be bytes");
            mpz_clear(cipher);
            return NULL;
        }
        
        mp_rsa_init(&temp_ctx, self->ctx.key_size, self->ctx.b);
        int result = mp_rsa_import_private_key(&temp_ctx, 
                                              (unsigned char *)PyBytes_AS_STRING(private_key_obj),
                                              PyBytes_GET_SIZE(private_key_obj));
        
        if (result != 0) {
            PyErr_SetString(PyExc_ValueError, "Invalid private key format");
            mp_rsa_clear(&temp_ctx);
            mpz_clear(cipher);
            return NULL;
        }
        
        ctx_to_use = &temp_ctx;
    }
    
    // Decrypt the cipher
    mpz_t message;
    mpz_init(message);
    
    if (mp_rsa_decrypt(ctx_to_use, cipher, message) != 0) {
        PyErr_SetString(PyExc_ValueError, "Decryption failed");
        if (private_key_obj && private_key_obj != Py_None) {
            mp_rsa_clear(&temp_ctx);
        }
        mpz_clear(cipher);
        mpz_clear(message);
        return NULL;
    }
    
    // Convert message to bytes
    size_t buffer_size = (mpz_sizeinbase(message, 2) + 7) / 8;
    void *buffer = malloc(buffer_size);
    
    if (!buffer) {
        PyErr_SetString(PyExc_MemoryError, "Failed to allocate memory for decrypted data");
        if (private_key_obj && private_key_obj != Py_None) {
            mp_rsa_clear(&temp_ctx);
        }
        mpz_clear(cipher);
        mpz_clear(message);
        return NULL;
    }
    
    size_t written;
    mpz_export(buffer, &written, 1, 1, 0, 0, message);
    
    PyObject *result = PyBytes_FromStringAndSize(buffer, written);
    
    // Clean up
    free(buffer);
    mpz_clear(cipher);
    mpz_clear(message);
    if (private_key_obj && private_key_obj != Py_None) {
        mp_rsa_clear(&temp_ctx);
    }
    
    return result;
}