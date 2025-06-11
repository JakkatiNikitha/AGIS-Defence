from setuptools import setup, find_packages

setup(
    name="agis_defence",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        'flask',
        'flask-cors',
        'psutil',
        'numpy',
        'pandas',
        'scikit-learn',
        'torch'
    ]
) 