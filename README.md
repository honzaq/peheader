# SFX Extra Data

Write and Read extra data after EXE file.

Code for Windows + VS2015 + for 32b files only

Command line:
* -w <file_path> will open existing EXE and write at the end 5000 file with random names and size
* -w <file_path> -files="\<file1\>;\<file2\>...": will open existing EXE and write list of files (separate by ';')
* -r <file_path>: will read existing EXE and read all header (speed test) + debug print result
