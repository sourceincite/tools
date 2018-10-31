# alpc-rpc-template

This is a template solution you can use for building ALPC/RPC clients on windows. For prototyping, I typically use [PyMSRPC](../pymsrpc) but for more serious work, then you can use this template to get started.

## Getting Started

* You will need your IDL of course, which you can just replace [rpc.idl](poc/rpc.idl) with.
  This will need to be in the similar format as provided and mIDA's direct output won't work so you will need to use [RpcView](http://www.rpcview.org/) or modify mIDA's output for it to compile and run correctly. 
* rpc_c.c doesn't actually exist on the filesystem and this file is generated on the fly at compile time with cl.exe
* The project configuration file's for Debug and Release are set correctly, don't change anything unless you know what your doing

### Installing

A step by step series of examples that tell you how to get a development env running

* Install Visual Studio 2017 (v141)
* Install Windows SDK 10.0.17134.0
* Update the [rpc.idl](poc/rpc.idl) file
* Modify [poc.cpp](poc/poc.cpp) to pwn
* Compile the project
* Run the built poc.exe and pwn

## Environment

This was tested on Windows 10 x86 Version 10.0.10240 with the latest patches at the time of release.

## Built With

* [Visual Studio 2017 (v141)](https://visualstudio.microsoft.com/downloads/) - IDE

## Authors

* **mr_me** - this repo

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details