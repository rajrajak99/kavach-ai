from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as f:
    long_description = f.read()

setup(
    name="kavach-ai",
    version="1.3.0",
    description="Autonomous Zero-Noise Code Security Inspector & 1-Click Surgical Patcher",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="Raja Rajak (@rajrajak99)",
    url="https://github.com/rajrajak99/kavach-ai",
    license="PolyForm-Noncommercial-1.0.0",
    packages=find_packages(include=["core*"]),
    py_modules=["cli", "ci_bot"],
    python_requires=">=3.9",
    install_requires=[
        "requests>=2.28.0",
    ],
    extras_require={
        "ui": ["streamlit>=1.35.0", "pandas>=2.0.0"],
        "dev": ["pytest>=8.0.0"],
    },
    entry_points={
        "console_scripts": [
            "kavach=cli:main",
            "kavach-ci=ci_bot:main",
            "autopatch=cli:main",
            "autopatch-ci=ci_bot:main",
        ],
    },
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "License :: Other/Proprietary License",
        "Programming Language :: Python :: 3",
        "Topic :: Security",
        "Topic :: Software Development :: Quality Assurance",
    ],
)
