from setuptools import setup, find_packages

setup(
    name="secure-btc-wallet",
    version="1.0.0",
    packages=find_packages(),
    install_requires=[
        "ecdsa",
        "requests",
        "base58"
    ],
    entry_points={
        "console_scripts": [
            "secure-btc-wallet=secure_btc_wallet.wallet_generator:main_loop",
        ],
    },
    python_requires='>=3.8',
    author="Slavik Khachatryan",
    description="A secure Bitcoin wallet generator in Python",
    url="https://github.com/ТВОЙ_USERNAME/secure-btc-wallet",
    license="MIT"
)
