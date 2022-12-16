// Include Python.h to not have problems with STL includes that come later on.
#define PY_SSIZE_T_CLEAN
#include <Python.h>

// Include the main Argon2 header file.
#include "argon2.h"

// Library includes
#include "encoding.h"

// STL includes
#include <string.h>
#include <math.h>

// This module brings over the reference implementation of Argon2 password hashing
// algorithm from c into python. It is based on the reference implementation that
// won the Password Hashing Competition (PHC) in 2015.

// Argon2i implementation
// =========================
// Argon2i is the safest of the three Argon2 variants. It is the only one that
// is resistant to side-channel attacks. It is also the slowest of the three
// variants. It is the recommended choice for password hashing and password-based
// key derivation.
static PyObject *
argon2_ihash (PyObject *self, PyObject *args, PyObject *kwargs) {
	// Clear the error indicator
	PyErr_Clear();
	// This will call argon2i_hash_raw() from the reference implementation.
	// Input parameters
	const char *pwd = NULL;
	size_t pwdlen = 0;
	const char *salt = NULL;
	size_t saltlen = 0;
	size_t iterations = 32;  // Default 32 iterations
	size_t memcost = 128;    // Default 128 KiB memory cost
	size_t parallelism = 1;  // Default 1 thread
	size_t hashlen = 64;     // Default 64 bytes
	// Output hash with its hash length
	char *hash = NULL;
	// The result of parsing will be stored here
	int result;
	// Parse the positional and optional keyword arguments
	static char *kwlist[] = {"pwd", "salt", "iterations", "memcost", "parallelism", "hashlen", NULL};
	if (!(result = PyArg_ParseTupleAndKeywords(args, kwargs, "y#y#|KKKK", kwlist, &pwd, &pwdlen, &salt, &saltlen, &iterations, &memcost, &parallelism, &hashlen))) {
		PyErr_SetString(PyExc_TypeError, "Could not parse the input parameters.");
		return NULL;
	}
	// Allocate memory for the hash
	hash = malloc(hashlen);
	if (hash == NULL) {
		PyErr_SetString(PyExc_MemoryError, "Could not allocate memory for the hash.");
		return NULL;
	}
	// Call the Argon2i hash function
	result = argon2i_hash_raw((const uint32_t) iterations, (const uint32_t) memcost, (const uint32_t) parallelism, pwd, pwdlen, salt, saltlen, hash, hashlen);
	if (result != ARGON2_OK) {
		PyErr_SetString(PyExc_RuntimeError, argon2_error_message(result));
		free(hash);
		return NULL;
	}
	// Return the hash
	return Py_BuildValue("y#", hash, hashlen);
}
// Same as above, but returns an enocded string instead of raw bytes
static PyObject *
argon2_ihash_encoded (PyObject *self, PyObject *args, PyObject *kwargs) {
	// Clear the error indicator
	PyErr_Clear();
	// This will call argon2i_hash_raw() from the reference implementation.
	// Input parameters
	const char *pwd = NULL;
	size_t pwdlen = 0;
	const char *salt = NULL;
	size_t saltlen = 0;
	size_t iterations = 32;  // Default 32 iterations
	size_t memcost = 128;    // Default 128 KiB memory cost
	size_t parallelism = 1;  // Default 1 thread
	size_t hashlen = 64;     // Default 64 bytes
	// Output encoded hash with its length
	char *encoded = NULL;
	// The result of parsing will be stored here
	int result;
	// Parse the positional and optional keyword arguments
	static char *kwlist[] = {"pwd", "salt", "iterations", "memcost", "parallelism", "hashlen", NULL};
	if (!(result = PyArg_ParseTupleAndKeywords(args, kwargs, "y#y#|KKKK", kwlist, &pwd, &pwdlen, &salt, &saltlen, &iterations, &memcost, &parallelism, &hashlen))) {
		PyErr_SetString(PyExc_TypeError, "Could not parse the input parameters.");
		return NULL;
	}
	// Allocate memory for the hash
	size_t encodedlen = 16 + numlen((uint32_t) memcost) + 3 + numlen((uint32_t) iterations) + 3 + numlen((uint32_t) parallelism) + 1 + b64len((uint32_t) saltlen) + 1 + b64len((uint32_t) hashlen) + 2;
	encoded = malloc(encodedlen);
	if (encoded == NULL) {
		PyErr_SetString(PyExc_MemoryError, "Could not allocate memory for the encoded hash.");
		return NULL;
	}
	// Call the Argon2i hash function
	result = argon2i_hash_encoded((const uint32_t) iterations, (const uint32_t) memcost, (const uint32_t) parallelism, pwd, pwdlen, salt, saltlen, hashlen, encoded, encodedlen);
	if (result != ARGON2_OK) {
		PyErr_SetString(PyExc_RuntimeError, argon2_error_message(result));
		free(encoded);
		return NULL;
	}
	// Return the hash
	return Py_BuildValue("y#", encoded, strlen(encoded));
}

// Argon2d implementation
// =========================
// Argon2d is the fastest of the three Argon2 variants. It is the only one that
// is resistant to GPU cracking attacks. It is also the only one that is
// resistant to tradeoff attacks. It is the recommended choice for password
// hashing and password-based key derivation on GPU cracking machines.
static PyObject *
argon2_dhash (PyObject *self, PyObject *args, PyObject *kwargs) {
	// Clear the error indicator
	PyErr_Clear();
	// This will call argon2i_hash_raw() from the reference implementation.
	// Input parameters
	const char *pwd = NULL;
	size_t pwdlen = 0;
	const char *salt = NULL;
	size_t saltlen = 0;
	size_t iterations = 32;  // Default 32 iterations
	size_t memcost = 128;    // Default 128 KiB memory cost
	size_t parallelism = 1;  // Default 1 thread
	size_t hashlen = 64;     // Default 64 bytes
	// Output hash with its hash length
	char *hash = NULL;
	// The result of parsing will be stored here
	int result;
	// Parse the positional and optional keyword arguments
	static char *kwlist[] = {"pwd", "salt", "iterations", "memcost", "parallelism", "hashlen", NULL};
	if (!(result = PyArg_ParseTupleAndKeywords(args, kwargs, "y#y#|KKKK", kwlist, &pwd, &pwdlen, &salt, &saltlen, &iterations, &memcost, &parallelism, &hashlen))) {
		PyErr_SetString(PyExc_TypeError, "Could not parse the input parameters.");
		return NULL;
	}
	// Allocate memory for the hash
	hash = malloc(hashlen);
	if (hash == NULL) {
		PyErr_SetString(PyExc_MemoryError, "Could not allocate memory for the hash.");
		return NULL;
	}
	// Call the Argon2i hash function
	result = argon2d_hash_raw((const uint32_t) iterations, (const uint32_t) memcost, (const uint32_t) parallelism, pwd, pwdlen, salt, saltlen, hash, hashlen);
	if (result != ARGON2_OK) {
		PyErr_SetString(PyExc_RuntimeError, argon2_error_message(result));
		free(hash);
		return NULL;
	}
	// Return the hash
	return Py_BuildValue("y#", hash, hashlen);
}
// Same as above, but returns an enocded string instead of raw bytes
static PyObject *
argon2_dhash_encoded (PyObject *self, PyObject *args, PyObject *kwargs) {
	// Clear the error indicator
	PyErr_Clear();
	// This will call argon2i_hash_raw() from the reference implementation.
	// Input parameters
	const char *pwd = NULL;
	size_t pwdlen = 0;
	const char *salt = NULL;
	size_t saltlen = 0;
	size_t iterations = 32;  // Default 32 iterations
	size_t memcost = 128;    // Default 128 KiB memory cost
	size_t parallelism = 1;  // Default 1 thread
	size_t hashlen = 64;     // Default 64 bytes
	// Output encoded hash with its length
	char *encoded = NULL;
	// The result of parsing will be stored here
	int result;
	// Parse the positional and optional keyword arguments
	static char *kwlist[] = {"pwd", "salt", "iterations", "memcost", "parallelism", "hashlen", NULL};
	if (!(result = PyArg_ParseTupleAndKeywords(args, kwargs, "y#y#|KKKK", kwlist, &pwd, &pwdlen, &salt, &saltlen, &iterations, &memcost, &parallelism, &hashlen))) {
		PyErr_SetString(PyExc_TypeError, "Could not parse the input parameters.");
		return NULL;
	}
	// Allocate memory for the hash
	size_t encodedlen = 16 + numlen((uint32_t) memcost) + 3 + numlen((uint32_t) iterations) + 3 + numlen((uint32_t) parallelism) + 1 + b64len((uint32_t) saltlen) + 1 + b64len((uint32_t) hashlen) + 2;
	encoded = malloc(encodedlen);
	if (encoded == NULL) {
		PyErr_SetString(PyExc_MemoryError, "Could not allocate memory for the encoded hash.");
		return NULL;
	}
	// Call the Argon2i hash function
	result = argon2d_hash_encoded((const uint32_t) iterations, (const uint32_t) memcost, (const uint32_t) parallelism, pwd, pwdlen, salt, saltlen, hashlen, encoded, encodedlen);
	if (result != ARGON2_OK) {
		PyErr_SetString(PyExc_RuntimeError, argon2_error_message(result));
		free(encoded);
		return NULL;
	}
	// Return the hash
	return Py_BuildValue("y#", encoded, strlen(encoded));
}

// Argon2id implementation
// =========================
// Argon2id is a hybrid of Argon2i and Argon2d. It is neither the fastest nor
// the safest of the three Argon2 variants, but it does provide a nice balance
// between the two.
static PyObject *
argon2_idhash (PyObject *self, PyObject *args, PyObject *kwargs) {
	// Clear the error indicator
	PyErr_Clear();
	// This will call argon2i_hash_raw() from the reference implementation.
	// Input parameters
	const char *pwd = NULL;
	size_t pwdlen = 0;
	const char *salt = NULL;
	size_t saltlen = 0;
	size_t iterations = 32;  // Default 32 iterations
	size_t memcost = 128;    // Default 128 KiB memory cost
	size_t parallelism = 1;  // Default 1 thread
	size_t hashlen = 64;     // Default 64 bytes
	// Output hash with its hash length
	char *hash = NULL;
	// The result of parsing will be stored here
	int result;
	// Parse the positional and optional keyword arguments
	static char *kwlist[] = {"pwd", "salt", "iterations", "memcost", "parallelism", "hashlen", NULL};
	if (!(result = PyArg_ParseTupleAndKeywords(args, kwargs, "y#y#|KKKK", kwlist, &pwd, &pwdlen, &salt, &saltlen, &iterations, &memcost, &parallelism, &hashlen))) {
		PyErr_SetString(PyExc_TypeError, "Could not parse the input parameters.");
		return NULL;
	}
	// Allocate memory for the hash
	hash = malloc(hashlen);
	if (hash == NULL) {
		PyErr_SetString(PyExc_MemoryError, "Could not allocate memory for the hash.");
		return NULL;
	}
	// Call the Argon2i hash function
	result = argon2id_hash_raw((const uint32_t) iterations, (const uint32_t) memcost, (const uint32_t) parallelism, pwd, pwdlen, salt, saltlen, hash, hashlen);
	if (result != ARGON2_OK) {
		PyErr_SetString(PyExc_RuntimeError, argon2_error_message(result));
		free(hash);
		return NULL;
	}
	// Return the hash
	return Py_BuildValue("y#", hash, hashlen);
}
// Same as above, but returns an enocded string instead of raw bytes
static PyObject *
argon2_idhash_encoded (PyObject *self, PyObject *args, PyObject *kwargs) {
	// Clear the error indicator
	PyErr_Clear();
	// This will call argon2i_hash_raw() from the reference implementation.
	// Input parameters
	const char *pwd = NULL;
	size_t pwdlen = 0;
	const char *salt = NULL;
	size_t saltlen = 0;
	size_t iterations = 32;  // Default 32 iterations
	size_t memcost = 128;    // Default 128 KiB memory cost
	size_t parallelism = 1;  // Default 1 thread
	size_t hashlen = 64;     // Default 64 bytes
	// Output encoded hash with its length
	char *encoded = NULL;
	// The result of parsing will be stored here
	int result;
	// Parse the positional and optional keyword arguments
	static char *kwlist[] = {"pwd", "salt", "iterations", "memcost", "parallelism", "hashlen", NULL};
	if (!(result = PyArg_ParseTupleAndKeywords(args, kwargs, "y#y#|KKKK", kwlist, &pwd, &pwdlen, &salt, &saltlen, &iterations, &memcost, &parallelism, &hashlen))) {
		PyErr_SetString(PyExc_TypeError, "Could not parse the input parameters.");
		return NULL;
	}
	// Allocate memory for the hash
	size_t encodedlen = 16 + numlen((uint32_t) memcost) + 3 + numlen((uint32_t) iterations) + 3 + numlen((uint32_t) parallelism) + 1 + b64len((uint32_t) saltlen) + 1 + b64len((uint32_t) hashlen) + 2;
	encoded = malloc(encodedlen);
	if (encoded == NULL) {
		PyErr_SetString(PyExc_MemoryError, "Could not allocate memory for the encoded hash.");
		return NULL;
	}
	// Call the Argon2i hash function
	result = argon2id_hash_encoded((const uint32_t) iterations, (const uint32_t) memcost, (const uint32_t) parallelism, pwd, pwdlen, salt, saltlen, hashlen, encoded, encodedlen);
	if (result != ARGON2_OK) {
		PyErr_SetString(PyExc_RuntimeError, argon2_error_message(result));
		free(encoded);
		return NULL;
	}
	// Return the hash
	return Py_BuildValue("y#", encoded, strlen(encoded));
}

// Custom verification function
// Infers the type of the hash from the encoded string
static PyObject *
argon2_check (PyObject *self, PyObject *args, PyObject *kwargs) {
	// Clear the error indicator
	PyErr_Clear();
	// Input parameters
	const char *encoded = NULL;
	size_t encodedlen = 0;
	const char *pwd = NULL;
	size_t pwdlen = 0;
	// The result of parsing will be stored here
	int result;
	// Parse the positional and optional keyword arguments
	static char *kwlist[] = {"encoded", "pwd", NULL};
	if (!(result = PyArg_ParseTupleAndKeywords(args, kwargs, "y#y#", kwlist, &encoded, &encodedlen, &pwd, &pwdlen))) {
		PyErr_SetString(PyExc_TypeError, "Could not parse the input parameters.");
		return NULL;
	}
	// Infer the type of the hash from the encoded string
	argon2_type type;
	if (encoded == NULL) {
		PyErr_SetString(PyExc_ValueError, "The encoded hash is NULL.");
		return NULL;
	} else if (encoded[7] == 'i' && encoded[8] == 'd') {
		type = Argon2_id;
	} else if (encoded[7] == 'i') {
		type = Argon2_i;
	} else if (encoded[7] == 'd') {
		type = Argon2_d;
	} else {
		PyErr_SetString(PyExc_ValueError, "Could not infer the type of the hash from the encoded string.");
		return NULL;
	}
	// Verify the password
	result = argon2_verify(encoded, pwd, pwdlen, type);
	// Return the hash
	return Py_BuildValue("i", result);
}

static PyMethodDef Argon2Methods[] = {
	{"ihash", (PyCFunction)(void(*)(void)) argon2_ihash, METH_VARARGS | METH_KEYWORDS, "Argon2i raw hash function"},
	{"ihash_encoded", (PyCFunction)(void(*)(void)) argon2_ihash_encoded, METH_VARARGS | METH_KEYWORDS, "Argon2i encoded hash function"},
	{"dhash", (PyCFunction)(void(*)(void)) argon2_dhash, METH_VARARGS | METH_KEYWORDS, "Argon2d raw hash function"},
	{"dhash_encoded", (PyCFunction)(void(*)(void)) argon2_dhash_encoded, METH_VARARGS | METH_KEYWORDS, "Argon2d encoded hash function"},
	{"idhash", (PyCFunction)(void(*)(void)) argon2_idhash, METH_VARARGS | METH_KEYWORDS, "Argon2id raw hash function"},
	{"idhash_encoded", (PyCFunction)(void(*)(void)) argon2_idhash_encoded, METH_VARARGS | METH_KEYWORDS, "Argon2id encoded hash function"},
	{"check", (PyCFunction)(void(*)(void)) argon2_check, METH_VARARGS | METH_KEYWORDS, "Argon2 verification function"},
	{NULL, NULL, 0, NULL}        /* Sentinel */
};

static struct PyModuleDef argon2module = {
	PyModuleDef_HEAD_INIT,
	"argon2",   /* name of module */
	NULL, /* module documentation, may be NULL */
	-1,       /* size of per-interpreter state of the module,
				or -1 if the module keeps state in global variables. */
	Argon2Methods
};

PyMODINIT_FUNC
PyInit_argon2(void)
{
	return PyModule_Create(&argon2module);
}