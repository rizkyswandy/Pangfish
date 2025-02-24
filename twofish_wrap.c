#include <Python.h>
#include <string.h>
#include "twofish.h"

typedef struct {
    PyObject_HEAD
    TWOFISH_CTX ctx;
} TwofishObject;

static void
Twofish_dealloc(TwofishObject *self)
{
    twofish_free_ctx(&self->ctx);
    Py_TYPE(self)->tp_free((PyObject *)self);
}

static PyObject *
Twofish_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
    TwofishObject *self;
    self = (TwofishObject *)type->tp_alloc(type, 0);
    if (self != NULL) {
        twofish_init_ctx(&self->ctx);
    }
    return (PyObject *)self;
}

static int
Twofish_init(TwofishObject *self, PyObject *args, PyObject *kwds)
{
    PyObject *key_obj = NULL;
    Py_buffer key;
    
    static char *kwlist[] = {"key", NULL};

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "O", kwlist, &key_obj))
        return -1;
    
    if (PyObject_GetBuffer(key_obj, &key, PyBUF_SIMPLE) < 0)
        return -1;
    
    if (key.len != 16 && key.len != 24 && key.len != 32) {
        PyErr_SetString(PyExc_ValueError, "Key size must be 16, 24, or 32 bytes (128, 192, or 256 bits)");
        PyBuffer_Release(&key);
        return -1;
    }
    
    twofish_set_key(&self->ctx, key.buf, key.len * 8);
    PyBuffer_Release(&key);
    
    return 0;
}

static PyObject *
Twofish_encrypt(TwofishObject *self, PyObject *args)
{
    Py_buffer data;
    PyObject *result;
    char *buffer;
    
    if (!PyArg_ParseTuple(args, "y*", &data))
        return NULL;
    
    if (data.len != 16) {
        PyErr_SetString(PyExc_ValueError, "Data must be 16 bytes long");
        PyBuffer_Release(&data);
        return NULL;
    }
    
    result = PyBytes_FromStringAndSize(NULL, data.len);
    if (result == NULL) {
        PyBuffer_Release(&data);
        return NULL;
    }
    
    buffer = PyBytes_AS_STRING(result);
    memcpy(buffer, data.buf, data.len);
    twofish_encrypt(&self->ctx, (BYTE*)buffer);
    
    PyBuffer_Release(&data);
    return result;
}

static PyObject *
Twofish_decrypt(TwofishObject *self, PyObject *args)
{
    Py_buffer data;
    PyObject *result;
    char *buffer;
    
    if (!PyArg_ParseTuple(args, "y*", &data))
        return NULL;
    
    if (data.len != 16) {
        PyErr_SetString(PyExc_ValueError, "Data must be 16 bytes long");
        PyBuffer_Release(&data);
        return NULL;
    }
    
    result = PyBytes_FromStringAndSize(NULL, data.len);
    if (result == NULL) {
        PyBuffer_Release(&data);
        return NULL;
    }
    
    buffer = PyBytes_AS_STRING(result);
    memcpy(buffer, data.buf, data.len);
    twofish_decrypt(&self->ctx, (BYTE*)buffer);
    
    PyBuffer_Release(&data);
    return result;
}

static PyMethodDef Twofish_methods[] = {
    {"encrypt", (PyCFunction)Twofish_encrypt, METH_VARARGS,
     "Encrypt a 16-byte block with Twofish"},
    {"decrypt", (PyCFunction)Twofish_decrypt, METH_VARARGS,
     "Decrypt a 16-byte block with Twofish"},
    {NULL}  /* Sentinel */
};

static PyTypeObject TwofishType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    .tp_name = "Twofish",
    .tp_doc = "Pangfish encryption algorithm",
    .tp_basicsize = sizeof(TwofishObject),
    .tp_itemsize = 0,
    .tp_flags = Py_TPFLAGS_DEFAULT,
    .tp_new = Twofish_new,
    .tp_init = (initproc)Twofish_init,
    .tp_dealloc = (destructor)Twofish_dealloc,
    .tp_methods = Twofish_methods,
};

static PyMethodDef module_methods[] = {
    {NULL}  /* Sentinel */
};

static struct PyModuleDef pangfishmodule = {
    PyModuleDef_HEAD_INIT,
    "_twofish",
    "Pangfish encryption module",
    -1,
    module_methods
};

PyMODINIT_FUNC
PyInit__twofish(void)
{
    PyObject *m;
    
    if (PyType_Ready(&TwofishType) < 0)
        return NULL;

    m = PyModule_Create(&pangfishmodule);
    if (m == NULL)
        return NULL;

    Py_INCREF(&TwofishType);
    if (PyModule_AddObject(m, "Twofish", (PyObject *)&TwofishType) < 0) {
        Py_DECREF(&TwofishType);
        Py_DECREF(m);
        return NULL;
    }

    return m;
}