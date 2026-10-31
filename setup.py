from setuptools import setup, find_packages

setup(
    name="kavach-ai",
    version="1.2.0",
    description="Autonomous Zero-Noise Code Security Inspector & 1-Click Surgical Patcher",
    long_description=open("README.md", encoding="utf-8").read(),
    long_description_content_type="text/markdown",
    author="Raja Rajak (@rajrajak99)",
    url="https://github.com/rajrajak99/kavach-ai",
    license="MIT",
    packages=find_packages(include=["core*", "samples*"]),
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
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Topic :: Security",
        "Topic :: Software Development :: Quality Assurance",
    ],
)
