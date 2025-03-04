#!/bin/bash

# copy config example files
if ! [ -f "config.json" ]; then
  cp -v "scripts/config.example.json" "config.json"
fi

