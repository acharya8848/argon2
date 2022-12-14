from pathlib import Path
from setuptools import Extension, setup

setup(
	ext_modules=[
		Extension(
			name = "argon2",  # as it would be imported
							# may include packages/namespaces separated by `.`
			include_dirs = ["include"],
			sources = [
				"src/argon2module.c",
				"src/argon2.c", "src/core.c",
				"src/encoding.c",
				"src/thread.c", 
				"src/blake2/blake2b.c",
				"src/opt.c",
			],
		),
	]
)