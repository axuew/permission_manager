from setuptools import setup

with open("README.md", "r") as fh:
    long_description = fh.read()

setup(
    name="Flask-Perms",
    url="https://github.com/jrice128/permission_manager",
    project_urls={
        "Documentation": "https://github.com/jrice128/permission_manager/blob/master/README.md",
        "Code": "https://github.com/jrice128/permission_manager",
        "Issue tracker": "https://github.com/jrice128/permission_manager/issues",
    },
    license="MIT",
    author="Jeff Rice",
    author_email="jrice128@gmail.com",
    description="A permissions and access control system for Flask.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    packages=["flask_perms"],
    include_package_data=True,
    python_requires=">= 3.6",
    install_requires=["flask>=1.0.0", "flask-login>=0.4.1", "Flask-SQLAlchemy>=2.3.2",
                      "Jinja2>=2.10.1", "SQLAlchemy>=1.3.4"],

    classifiers=[
        "Development Status :: 3 - Alpha",
        "Environment :: Web Environment",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: Implementation :: CPython",
        "Programming Language :: Python :: Implementation :: PyPy",
        "Topic :: Internet :: WWW/HTTP :: Dynamic Content",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
)
