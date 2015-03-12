ngx\_v8 is an Nginx module that enables you to run any Javascript script Google's V8 Javascript Engine supports.

> _Nginx is a HTTP server and mail proxy server written by Igor Sysoev._ (quoted from [Nginx Official Site](http://nginx.net/))

**Specification Overview**

  * To use this module you need to specify "v8" directive at the location context in nginx.conf. This directive takes a Javascript script file path.
  * Javascript script need to have a function named "process" in the global scope. This function takes two parameters "request" and "response", and returns an integer value representing HTTP status code.
  * The "request" and "response" objects bridge the world between Javascript and C++. They will have a set of properties and functions enough to access browser-requested information and a response being created respectively. Only a few members are currently implemented.
  * You can find an example script [here](http://code.google.com/p/ngxv8/source/browse/trunk/examples/simple.js).