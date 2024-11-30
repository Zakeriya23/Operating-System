#!/bin/bash
#marcos chavez mchav2@pdx.edu
#zakeriya muhumed@pdx.edu

UPPER_BOUND=100

if [ $# -ge 1 ]; then
  UPPER_BOUND=$1
fi

for ((i=2; i<=UPPER_BOUND; i++)); do
  FACTORS=$(factor "$i")
  if [ "$(echo "$FACTORS" | wc -w)" -eq 2 ]; then
    echo "$i"
  fi
done


