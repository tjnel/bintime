# bintime

## Purpose
The goal of this script is to use pefile and system utilities to extract all relevant timestamps for one or more pe binary samples. This will help an analyst determine the probable lifespan of that sample.

## Installing

Running bintime is easy just install the one requirement and then point the script to the files you want to analyze. The pipenv.lock and requirements files are included for virtual environments.

### Prerequisites
You will need install pefile in order to run this script
```
sudo pip install pefile
``` 

## Usage

#### Options 
```
usage: bintime.py [-h] [-v] [-t] [-f] input

This is a script that will enumerate timestamps associated with binary files

positional arguments:
  input           file or directory to run bintime against

optional arguments:
  -h, --help      show this help message and exit
  -v, --verbose   increase output verbosity
  -t, --timeline  create a timeline from input
  -f, --full      output will display all timestamps
```

#### Simple usage against single file
```
python bintime.py test.exe
```

#### Run against directory with all timestamp details
```
python bintime.py directory/ -f
```

#### Run against directory and generating a timeline
```
python bintime.py directory/ -t
```

## Usage Video

The following is a youtube link explaining the to use this script.
[https://youtu.be/IYYY5Y_YpRw](https://youtu.be/IYYY5Y_YpRw)

## Built With

* [Python3](https://github.com/python/cpython)
* [pefile](https://github.com/erocarrera/pefile)
* [vis.js](http://visjs.org/)

## Authors

* **TJ Nel** - *Initial work* - [TJNel](https://github.com/tjnel)

See also the list of [contributors](https://github.com/tjnel/bintime/contributors) who participated in this project.

## License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details

## Acknowledgments

* Hat tip to [Ero Carrera](https://github.com/erocarrera) for creating [pefile](https://github.com/erocarrera/pefile)
* Hat tip to [Hexacorn](http://www.hexacorn.com/blog/) for writing a [blog](http://www.hexacorn.com/blog/2014/12/18/the-not-so-boring-land-of-borland-executables-part-2/) on alternative timestamps 