from setuptools import setup, find_packages

setup(
    name="pqvpn",
    version="0.2.0",
    packages=find_packages(),
    package_data={"pqvpn": ["README_QUICKSTART.yaml"]},
    install_requires=["cryptography>=42.0.0", "pyyaml>=6.0"],
    entry_points={"console_scripts": ["pqvpn=pqvpn.cli:main"]},
    author="Path-Quilt VPN",
    description="Decentralized P2P VPN with multi-hop pathlets",
)

install_requires = (
    [
        "cryptography>=42.0.0",
        "pyyaml>=6.0",
        "importlib-metadata",  # for relative imports
    ],
)
