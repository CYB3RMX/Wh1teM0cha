import setuptools

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setuptools.setup(
    name="wh1tem0cha",
    version="0.3",
    author="CYB3RMX",
    author_email="cyb3rmx0@gmail.com",
    description="Python Module for Parsing & Reverse Engineering Mach-O Executables.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/CYB3RMX/Wh1teM0cha",
    project_urls={
        "Bug Tracker": "https://github.com/CYB3RMX/Wh1teM0cha/issues",
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: GNU General Public License (GPL)",
        "Operating System :: OS Independent",
    ],
    package_dir={"": "src"},
    packages=setuptools.find_packages(where="src"),
    python_requires=">=3.9",
)