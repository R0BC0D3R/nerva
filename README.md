# NERVA

Copyright (c) 2018 - 2024 The NERVA Project. Copyright (c) 2014-2024 The Monero Project. Copyright (c) 2017-2018 The Masari Project. Portions Copyright (c) 2012-2013 The Cryptonote developers.


# Compiling Nerva from source 
Nerva used build scripts in the past that are inside `nerva/builder/` but we discontinued that in favor of just using `make`. If you prefer that way of building see `nerva/builder/build` script and the other files in there and make appropriate changes to work for your OS.

When using `make` to compile, executable files will be created in a directory similar to this:

`nerva/build/[YOUR_SYSTEM]/[YOUR_BRANCH]/release/bin/`


## Dependencies
First you'll need to install required dependencies for your operating system.

### Debian/Ubuntu
```bash
sudo apt update && sudo apt install build-essential cmake pkg-config libboost-all-dev libssl-dev libzmq3-dev libpgm-dev libunbound-dev libsodium-dev git
```

### Windows

#### Install MSYS2 
Install MSYS2 (Software Distribution and Building Platform for Windows): 
[MSYS2 Website][msys2-link]

Open MSYS2 Shell and run below to update: 
```bash
pacman -Syu
```

#### Install NERVA dependancies 
You'll need below dependencies to build Nerva.  Run command for your target Windows version. 
Windows 64-bit:
```bash
pacman -S mingw-w64-x86_64-toolchain make mingw-w64-x86_64-cmake mingw-w64-x86_64-boost mingw-w64-x86_64-openssl mingw-w64-x86_64-zeromq mingw-w64-x86_64-libsodium mingw-w64-x86_64-hidapi mingw-w64-x86_64-unbound git
```

Windows 32-bit: 
```bash
pacman -S mingw-w64-i686-toolchain make mingw-w64-i686-cmake mingw-w64-i686-boost mingw-w64-i686-openssl mingw-w64-i686-zeromq mingw-w64-i686-libsodium mingw-w64-i686-hidapi mingw-w64-i686-unbound git
```

### macOS
If you do not have it already, install Xcode, command line tools first: 
```bash
xcode-select --install
```
You won't be able to do this through SSH as when you run it, you get pop-up box where you need to press Install and agree to license. 

Now install Homebrew: 
```bash
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install.sh)"
```
After installation, follow instructions to add brew to your PATH.

Once you have brew, you can install dependencies using provided Brewfile located under: 
`nerva\contrib\brew\Brewfile` 

```bash
brew update && brew bundle --file=contrib/brew/Brewfile
```
You need to be in `/nerva/` directory and nerva project needs to be cloned arlready so see Cloning repository below


## Clone NERVA repository

In terminal/MSYS2 shell, go to directory where you want to clone NERVA (ex: `/home/USER_NAME` or `/c/msys64/usr/local`) and clone repository:
```bash
git clone --recursive https://github.com/nerva-project/nerva.git
```
This will create `nerva` directory. 

To clone specific branch add `--branch` at the end of git command: 
```bash
git clone --recursive https://github.com/nerva-project/nerva.git --branch your-branch-name
```


## Build Nerva project
Make sure you're in `nerva` directory and start build process: 

### Linux/macOS
```bash
make
```

### Windows 
```bash
make release-static-win64
```
or
```bash
make release-static-win32
```

If your CPU does not support AES instructions, you can build using:
```bash
make release-noaes
```

See Makefile for other options


## Help Me! 

[GitHub docs][nerva-docs-link] is your friend, or head to [Discord][nerva-discord-link] to talk to a person. 



<!-- Reference links -->
[nerva-discord-link]: https://discord.gg/jsdbEns
[nerva-docs-link]: https://docs.nerva.one
[msys2-link]: https://www.msys2.org
