#!/bin/bash

gcc src/sender.c src/selectserver -o sender
gcc src/receiver.c -o receiver