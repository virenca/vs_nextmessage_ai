#!/bin/sh

# install essential build tools
apt update && apt install -y build-essential cmake

# install ninja build for fast compilation
apt install ninja-build

# assume we are at folder ~/
cd ~/

# clone llama.cpp
git clone https://github.com/ggerganov/llama.cpp
cd llama.cpp

# build as static lib
# cmake -B build -G Ninja && ninja -C build

# build as shared lib
cmake -B build -G Ninja -DBUILD_SHARED_LIBS=ON -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release

# download mistral model
cd models/
wget https://huggingface.co/TheBloke/Mistral-7B-Instruct-v0.1-GGUF/resolve/main/mistral-7b-instruct-v0.1.Q4_K_M.gguf

# cd ~/llama.cpp
cd .. 
./build/bin/llama-cli -m models/mistral-7b-instruct-v0.1.Q4_K_M.gguf -p "Explain memory management in C++." -t 4

