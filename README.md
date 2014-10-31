sm_api
======

How to git clone the project with submodule
----
```
git clone --recursive https://github.com/zlargon/sm_api.git
```
or
```
git clone https://github.com/zlargon/sm_api.git
git submodule init
git submodule update
```

How to build on OS X
----
replace the `Makefile` in khttp library
```
cd lib/khttp
cp Makefile.mac Makefile
```
