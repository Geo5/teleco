#!/bin/bash

for w0 in 2 3 4 5 6
do
    sed -i "s/set w0 [0-9]\+/set w0 $w0/g" DiffServWRR.tcl
    ns DiffServWRR.tcl
done