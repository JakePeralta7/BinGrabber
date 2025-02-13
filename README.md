# BinGrabber
![GitHub Created At](https://img.shields.io/github/created-at/JakePeralta7/BinGrabber?color=blue)
![GitHub contributors](https://img.shields.io/github/contributors/JakePeralta7/BinGrabber)
![GitHub Release](https://img.shields.io/github/v/release/JakePeralta7/BinGrabber)
[![GitHub Issues](https://img.shields.io/github/issues/JakePeralta7/BinGrabber)](https://github.com/JakePeralta7/BinGrabber/issues)
[![Build, Test & Release](https://github.com/JakePeralta7/BinGrabber/actions/workflows/build_test_and_release.yml/badge.svg)](https://github.com/JakePeralta7/BinGrabber/actions/workflows/build_test_and_release.yml)

Grabs running process binaries and saves them with SHA256 hash names.
 
## Build
```
windres version.rc -o version.o
gcc .\src\bin_grabber.c version.o -o bin_grabber_x64.exe -s -m64
```

## Usage
```
bin_grabber_x64.exe <output_directory>
```
