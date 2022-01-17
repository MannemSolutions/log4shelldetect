# log4shelldetect

Scans a file or folder recursively for jar files that contain log4j by inspecting the class paths inside the jar.

Use this info to find out if it may be vulnerable to Log4Shell (CVE-2021-44228).

## Install
Just download the correct version / platform from [Releases](https://github.com/MannemSolutions/log4shelldetect/releases) and run.
Or download the container image from [dockerhub](https://hub.docker.com/r/mannemsolutions/log4shelldetect).
### Example:

```
cd /tmp
curl -L https://github.com/MannemSolutions/log4shelldetect/releases/download/v0.9.1/log4shelldetect-v0.9.1-linux-amd64.tar.gz | tar -xvz
./log4shelldetect -hash -l4jversion -ok test/
```

### Example result:
```
84057480ba7da6fb6d9ea50c53a00848315833c1f34bf8f4a47f11a14499ae3f 2.16.0     LOG4J   test/dir/log4j-core-2.16.0b.jar
UNKNOWN                                                          2.13.3     PATCHED test/dir2/velocity-1.1.9.jar
e4abe8708d914d20887d0704ea42b1914eb50e638c3016d8f8d312b39592a768 2.13.3     LOG4J   test/dir3/velocity-1.1.9.jar
UNKNOWN                                                          2.0.0-beta PATCHED test/file/log4j-core-2.0-beta6.jar
e4abe8708d914d20887d0704ea42b1914eb50e638c3016d8f8d312b39592a768 2.13.3     LOG4J   test/file/velocity-1.1.9.war
```

In this result:
* hash of the log4j/core/lookup/JndiLookup.class in the jar file is printed
  * if existing
  * when multiple versions are embedded, only for the lowest version detected
  * only printed with `-hash` option
* Version of log4j is printed
  * only when it is listed in a file `META-INF/maven/org.apache.logging.log4j/log4j-core/pom.properties`
  * can be subfolder (e.a. `a/b/c/META-INF/...`)
* lists the state:
  * LOG4J: log4j was detected
  * WORKAROUND: log4j was detected, but log4j/core/lookup/JndiLookup.class was removed as a workaround to the CVE issue
  * NOLOG4J: log4j was not detected
  * EMPTY: The file is not a jar, but an empty file
  * NOFILE: The file is a symlink pointing to a file that does not exist
  * NOZIP: The file cannot be opened with the zip module
  * UNKNOWN: a weird situation has occurred. Run with -debug to get more details...
* lists the path to the jar or war file

## Issues
If you run into any issue, please let us know (file an issue on github, or mail me at sebas@mannemsolutions.nl).

## License

Code here is released to the public domain under [unlicense](/LICENSE).

With the exception of:
* `./test/*/velocity-1.1.9.*` which is an example vulnerable `.jar` file part of [Velocity](https://github.com/PaperMC/Velocity) which is licensed under GPLv3.
* All the `test/*/log4j*` files which are licensed under the Apache 2.0 license...
