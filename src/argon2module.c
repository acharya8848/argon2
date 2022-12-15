// Include Python.h to not have problems with STL includes that come later on.
#define PY_SSIZE_T_CLEAN
#include <Python.h>

// Include the main Argon2 header file.
#include "argon2.h"

// STL includes

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
	size_t iterations = 512; // Default 512 iterations
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
	// printf("\r\nTime cost: %llu\r\n", iterations);
	// printf("Memory cost: %llu\r\n", memcost);
	// printf("Parallelism: %llu\r\n", parallelism);
	// printf("Password: %s\r\n", pwd);
	// printf("Password length: %llu\r\n", pwdlen);
	// printf("Salt: %s\r\n", salt);
	// printf("Salt length: %llu\r\n", saltlen);
	// printf("Hash length: %llu\r\n\r\n", hashlen);
	// Allocate memory for the hash
	hash = malloc(hashlen);
	if (hash == NULL) {
		PyErr_SetString(PyExc_MemoryError, "Could not allocate memory for the hash.");
		return NULL;
	}
	// Call the Argon2i hash function
	result = argon2i_hash_raw((const uint32_t) iterations, (const uint32_t) memcost, (const uint32_t) parallelism, pwd, pwdlen, salt, saltlen, hash, hashlen);
	if (result != ARGON2_OK) {
		PyErr_SetString(PyExc_RuntimeError, "Could not hash the password.");
		free(hash);
		return NULL;
	}
	// Return the hash
	return Py_BuildValue("y#", hash, hashlen);
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
	size_t iterations = 512; // Default 512 iterations
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
	// printf("\r\nTime cost: %llu\r\n", iterations);
	// printf("Memory cost: %llu\r\n", memcost);
	// printf("Parallelism: %llu\r\n", parallelism);
	// printf("Password: %s\r\n", pwd);
	// printf("Password length: %llu\r\n", pwdlen);
	// printf("Salt: %s\r\n", salt);
	// printf("Salt length: %llu\r\n", saltlen);
	// printf("Hash length: %llu\r\n\r\n", hashlen);
	// Allocate memory for the hash
	hash = malloc(hashlen);
	if (hash == NULL) {
		PyErr_SetString(PyExc_MemoryError, "Could not allocate memory for the hash.");
		return NULL;
	}
	// Call the Argon2i hash function
	result = argon2d_hash_raw((const uint32_t) iterations, (const uint32_t) memcost, (const uint32_t) parallelism, pwd, pwdlen, salt, saltlen, hash, hashlen);
	if (result != ARGON2_OK) {
		PyErr_SetString(PyExc_RuntimeError, "Could not hash the password.");
		free(hash);
		return NULL;
	}
	// Return the hash
	return Py_BuildValue("y#", hash, hashlen);
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
	size_t iterations = 512; // Default 512 iterations
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
	// printf("\r\nTime cost: %llu\r\n", iterations);
	// printf("Memory cost: %llu\r\n", memcost);
	// printf("Parallelism: %llu\r\n", parallelism);
	// printf("Password: %s\r\n", pwd);
	// printf("Password length: %llu\r\n", pwdlen);
	// printf("Salt: %s\r\n", salt);
	// printf("Salt length: %llu\r\n", saltlen);
	// printf("Hash length: %llu\r\n\r\n", hashlen);
	// Allocate memory for the hash
	hash = malloc(hashlen);
	if (hash == NULL) {
		PyErr_SetString(PyExc_MemoryError, "Could not allocate memory for the hash.");
		return NULL;
	}
	// Call the Argon2i hash function
	result = argon2id_hash_raw((const uint32_t) iterations, (const uint32_t) memcost, (const uint32_t) parallelism, pwd, pwdlen, salt, saltlen, hash, hashlen);
	if (result != ARGON2_OK) {
		PyErr_SetString(PyExc_RuntimeError, "Could not hash the password.");
		free(hash);
		return NULL;
	}
	// Return the hash
	return Py_BuildValue("y#", hash, hashlen);
}

static PyMethodDef Argon2Methods[] = {
	{"test", argon2_test, METH_VARARGS, "Test bytes argument parsing"},
	{"ihash", (PyCFunction)(void(*)(void)) argon2_ihash, METH_VARARGS | METH_KEYWORDS, "Argon2i hash function"},
	{"dhash", (PyCFunction)(void(*)(void)) argon2_dhash, METH_VARARGS | METH_KEYWORDS, "Argon2d hash function"},
	{"idhash", (PyCFunction)(void(*)(void)) argon2_idhash, METH_VARARGS | METH_KEYWORDS, "Argon2id hash function"},
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