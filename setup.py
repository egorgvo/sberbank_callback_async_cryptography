import pathlib
from setuptools import setup

# The directory containing this file
HERE = pathlib.Path(__file__).parent

# The text of the README file
README = (HERE / "README.md").read_text()

# This call to setup() does all the work
setup(
    name="sberbank-async-cryptography",
    version="1.0.0",
    description="Python implementation of Sberbank signature verification (using async cryptography).",
    long_description=README,
    long_description_content_type="text/markdown",
    url="https://github.com/egorgvo/sberbank_callback_async_cryptography",
    author="Egor Gvo",
    author_email="work.egvo@ya.ru",
    license="MIT",
    classifiers=[
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
    ],
    packages=["sb_async_cryptography"],
    install_requires=["pycryptodomex==3.9.8", "cryptography==3.0"],
)
