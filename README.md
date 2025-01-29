# BinGrabber
[![Build & Release](https://github.com/JakePeralta7/BinGrabber/actions/workflows/build_and_release.yml/badge.svg)](https://github.com/JakePeralta7/BinGrabber/actions/workflows/build_and_release.yml)

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
