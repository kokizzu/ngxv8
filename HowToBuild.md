# Step 1 : Getting V8 #

At the beginning, You need to get [V8 JavaScript Engine](http://code.google.com/p/v8/) source code and build it. You can find the instruction at the V8 project site.

After the build process is succeeded, you would get the library named "libv8.so" which is made use of linking to ngx\_v8.


# Step 2: Getting Nginx #

You also have to get Nginx source code of course. Download a latest archive from the [Officeal Site](http://nginx.net/).

**I confirmed nginx-0.8.x on x86\_64 does not works due to some problem.** http://code.google.com/p/ngxv8/issues/detail?id=1 Thanks to ihanick.


# Step 3: Getting ngx\_v8 #

ngx\_v8 source code is hosted on this site. ngx\_v8 has only two files: "config" and "ngx\_http\_v8\_module.cc". "config" is a file containing module build information to tell Nginx that it is a module for you. In this file, you need to specify the location of V8. Change the path from my one to your one.

At last, you are in build stage. Like always go to the Nginx directory, configure, make, and make install as follows. At this time, you have to specify the path to ngx\_v8 directory containing "config" and "ngx\_http\_v8\_module.cc" using configure's "--add-module" parameter.$ cd ${NGINX_SRC}
$ ./configure --prefix=/path/to/installation --add-module=/path/to/ngx_v8
$ make
$ make install```